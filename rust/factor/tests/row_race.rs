//! Row m3-factor-race: every verifier's decision raced from one snapshot, and the invariants over random sequences.
mod common;

use std::collections::BTreeSet;

use base::{Effect, Guard, Row, Slot, Store, UnixTime};
use common::{
    Case, Mem, applied, attempts_row, count, rfc6238, seed_step, seen, stored, verify_once,
};
use factor::{
    Digits, Key, OtpAlg, OtpCode, OtpKey, Period, Phc, Record, RecoveryCode, RecoveryCount, Skew,
    Throttle, Totp, recovery_generate, recovery_verify,
};
use proptest::prelude::*;
use proptest::test_runner::{RngSeed, TestError, TestRunner};
use testkit::{Decide, Seeded, race, seeded};

type Boxed = Box<dyn std::error::Error>;
type Op = Box<dyn Fn(&mut Mem, &mut Seeded) -> Option<Effect<Key, Record>>>;

const NOW: UnixTime = UnixTime::new(1_111_111_109);

fn sha1_case() -> Result<Case, Boxed> {
    let cases = rfc6238();
    cases
        .into_iter()
        .find(|c| c.id == "b-sha1-1111111109")
        .ok_or_else(|| "case".into())
}

fn authenticator(c: &Case, skew: Skew) -> Result<Totp, Boxed> {
    let key = OtpKey::import(common::unhex(&c.secret).ok_or("hex")?)?;
    Ok(Totp::new(
        key,
        OtpAlg::Sha1,
        Digits::Eight,
        Period::new(c.step)?,
        skew,
    ))
}

/// The same effect as data a race can own: `Pending` gives out only a borrow.
fn owned(from: &Effect<Key, Record>, e: &mut Seeded) -> Option<Effect<Key, Record>> {
    let writes: Vec<(Key, Option<Record>)> = from
        .puts()
        .map(|(k, r, _)| (*k, Some(r.clone())))
        .chain(from.deletes().map(|k| (*k, None)))
        .collect();
    let write = |k: &Key| writes.iter().find(|(w, _)| w == k).map(|(_, r)| r.clone());
    let mut b = Effect::builder(e);
    for g in from.guards() {
        let k = **g.key();
        b = match (g, write(&k)) {
            (Guard::Absent(_), Some(Some(r))) => b.create(k, r, None),
            (Guard::Absent(_), _) => b.expect_absent(k),
            (Guard::Unchanged(_, v), Some(Some(r))) => b.update(k, &Row::new((), v), r, None),
            (Guard::Unchanged(_, v), Some(None)) => b.delete(k, &Row::new((), v)),
            (Guard::Unchanged(_, v), None) => b.expect(k, &Row::new((), v)),
            (Guard::Consume(_), _) => b.consume(k),
            _ => b,
        };
    }
    b.build().ok()
}

/// R3 and R4: the effect guards exactly the rows the decision loaded, and no put expires.
fn shaped(loaded: &[Key], effect: &Effect<Key, Record>) {
    let guarded: BTreeSet<Key> = effect.guards().map(|g| **g.key()).collect();
    assert_eq!(guarded, loaded.iter().copied().collect::<BTreeSet<_>>());
    assert!(effect.puts().all(|(_, _, expiry)| expiry.is_none()));
}

fn rows(loaded: &base::Rows<Key, Record>, key: Key) -> Option<Row<&Record>> {
    match loaded.get(&key)? {
        Slot::Row(r) => Some(Row::new(r.record(), r.version())),
        _ => None,
    }
}

fn totp_op(t: Totp, code: String) -> Op {
    Box::new(move |store, e| {
        let loaded = store.load(&[Key::Attempts, Key::TotpStep], NOW).ok()?;
        let attempts = rows(&loaded, Key::Attempts).and_then(|r| match r.record() {
            Record::Attempts(a) => Some(Row::new(a, r.version())),
            _ => None,
        });
        let step = rows(&loaded, Key::TotpStep).and_then(|r| match r.record() {
            Record::TotpStep(s) => Some(Row::new(s, r.version())),
            _ => None,
        });
        let permit = common::permit(attempts, NOW)?;
        let pending = t
            .verify(permit, &OtpCode::parse(&code).ok()?, step, e)
            .ok()?;
        shaped(&[Key::Attempts, Key::TotpStep], pending.effect());
        owned(pending.effect(), e)
    })
}

fn recovery_op(code: String) -> Op {
    Box::new(move |store, e| {
        let code = RecoveryCode::parse(&code).ok()?;
        let loaded = store.load(&[Key::Attempts, code.key()], NOW).ok()?;
        let attempts = rows(&loaded, Key::Attempts).and_then(|r| match r.record() {
            Record::Attempts(a) => Some(Row::new(a, r.version())),
            _ => None,
        });
        let hash = rows(&loaded, code.key()).and_then(|r| match r.record() {
            Record::Recovery(h) => Some(Row::new(h, r.version())),
            _ => None,
        });
        let permit = common::permit(attempts, NOW)?;
        let pending = recovery_verify(permit, &code, hash, e).ok()?;
        shaped(&[Key::Attempts, code.key()], pending.effect());
        owned(pending.effect(), e)
    })
}

/// A store holding the codes' rows and a stored step, and the texts of its codes.
fn start(step: u64, codes: u8) -> Result<(Mem, Vec<String>), Boxed> {
    let (mut store, mut e) = (Mem::new(), seeded(70));
    seed_step(&mut store, &mut e, step).ok_or("step")?;
    let pending = recovery_generate(RecoveryCount::new(codes)?, &mut e)?;
    let receipt = applied(&mut store, pending.effect(), NOW).ok_or("apply")?;
    let texts = pending
        .settle(receipt)?
        .iter()
        .map(|c| c.display().to_string())
        .collect();
    Ok((store, texts))
}

fn pair<'a>(a: &'a Op, b: &'a Op) -> [Decide<'a, Key, Record>; 2] {
    [a.as_ref(), b.as_ref()]
}

#[test]
fn read_set() -> Result<(), Boxed> {
    let c = sha1_case()?;
    let (store, codes) = start(37_037_030, 2)?;
    let first = codes.first().ok_or("code")?.clone();
    let ops: Vec<Op> = vec![
        totp_op(authenticator(&c, Skew::One)?, c.code.clone()),
        totp_op(authenticator(&c, Skew::One)?, "07081805".into()),
        recovery_op(first.clone()),
        recovery_op(first),
        recovery_op(codes.get(1).ok_or("code")?.clone()),
        recovery_op("0".repeat(24)),
    ];
    let conflicts: usize = ops
        .iter()
        .flat_map(|a| ops.iter().map(move |b| (a, b)))
        .map(|(a, b)| race(&store, &pair(a, b), NOW))
        .sum();
    assert!(conflicts > 0);
    Ok(())
}

#[test]
fn same_code_twice() -> Result<(), Boxed> {
    let (store, codes) = start(0, 1)?;
    let op = recovery_op(codes.first().ok_or("code")?.clone());
    // either order: one effect applies, and the other's decision is void
    assert_eq!(race(&store, &pair(&op, &op), NOW), 2);
    Ok(())
}

#[test]
fn two_guesses() -> Result<(), Boxed> {
    let c = sha1_case()?;
    let (store, _) = start(0, 1)?;
    let (a, b) = (
        totp_op(authenticator(&c, Skew::One)?, "00000001".into()),
        totp_op(authenticator(&c, Skew::One)?, "00000002".into()),
    );
    assert_eq!(race(&store, &pair(&a, &b), NOW), 2);
    Ok(())
}

fn config(cases: u32) -> ProptestConfig {
    ProptestConfig {
        cases,
        rng_seed: RngSeed::Fixed(0x5eed_0009),
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

fn fail(e: impl std::fmt::Debug) -> TestCaseError {
    TestCaseError::fail(format!("{e:?}"))
}

/// A presented code that is right at `case`'s time, or right but for the last digit.
fn presented(c: &Case, corrupt: bool) -> String {
    let mut code = c.code.clone();
    if corrupt {
        let last = code.pop().map_or('0', |d| {
            if d == '9' {
                '0'
            } else {
                char::from(u8::try_from(d).map_or(b'0', |b| b.saturating_add(1)))
            }
        });
        code.push(last);
    }
    code
}

type Plays = Vec<(usize, i8, bool, Option<usize>)>;

#[test]
fn counted_sequences() -> Result<(), TestError<Plays>> {
    let sha1: Vec<Case> = rfc6238()
        .into_iter()
        .filter(|c| c.alg == "sha1" && c.digits == 8)
        .collect();
    let plays = prop::collection::vec(
        (
            0..sha1.len(),
            -1i8..=1,
            any::<bool>(),
            prop::option::of(0usize..3),
        ),
        0..=10,
    );
    TestRunner::new(config(64)).run(&plays, |plays| {
        let (mut store, mut e) = (Mem::new(), seeded(5));
        let pending =
            recovery_generate(RecoveryCount::new(3).map_err(fail)?, &mut e).map_err(fail)?;
        let receipt = applied(&mut store, pending.effect(), NOW).ok_or_else(|| fail("apply"))?;
        let codes = pending.settle(receipt).map_err(fail)?;
        let (mut applied_verdicts, mut accepted, mut spent) = (0u32, None::<u64>, BTreeSet::new());
        for (i, offset, corrupt, recovery) in plays {
            let c = sha1.get(i).ok_or_else(|| fail("case"))?;
            let now = UnixTime::new(
                c.time
                    .saturating_add_signed(i64::from(offset) * i64::from(c.step)),
            );
            if let Some(code) = recovery.and_then(|r| codes.get(r)) {
                let (attempts, row) = (attempts_row(&mut store), stored(&mut store, code.key()));
                let hash = row.as_ref().and_then(|r| match r.record() {
                    Record::Recovery(h) => Some(Row::new(h, r.version())),
                    _ => None,
                });
                let permit = common::permit(attempts.as_ref().map(seen), now)
                    .ok_or_else(|| fail("permit"))?;
                let pending = recovery_verify(permit, code, hash, &mut e).map_err(fail)?;
                let receipt =
                    applied(&mut store, pending.effect(), now).ok_or_else(|| fail("apply"))?;
                let matched = pending.settle(receipt).map_err(fail)?.is_ok();
                // a code matches the first time and never again (R33)
                prop_assert_eq!(matched, spent.insert(code.key()));
            } else {
                let t = authenticator(c, Skew::One).map_err(fail)?;
                let code = OtpCode::parse(&presented(c, corrupt)).map_err(fail)?;
                let verdict = verify_once(&mut store, &mut e, &t, &code, now)
                    .ok_or_else(|| fail("verify"))?;
                if let Ok(m) = verdict {
                    prop_assert!(accepted.is_none_or(|a| m.step() > a), "accepted steps rise");
                    accepted = Some(m.step());
                }
            }
            // the count rises by one per applied verdict, matches included (R12)
            applied_verdicts += 1;
            prop_assert_eq!(count(&mut store), Some(applied_verdicts));
        }
        if let Some(row) = attempts_row(&mut store) {
            let reset = Throttle::reset(seen(&row), &mut e);
            applied(&mut store, &reset, NOW).ok_or_else(|| fail("reset"))?;
            prop_assert_eq!(count(&mut store), None);
        }
        Ok(())
    })
}

type Constructed = (Vec<u8>, u8, u32, u64, Option<u64>, String);

fn sized_key() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 16..=64)
}

#[test]
fn no_internal_totp() -> Result<(), TestError<Constructed>> {
    let digits = prop_oneof![Just(6usize), Just(8usize)].prop_flat_map(|n| {
        prop::collection::vec(0u8..10, n)
            .prop_map(|d| d.iter().map(|d| char::from(b'0' + d)).collect::<String>())
    });
    let inputs = (
        sized_key(),
        0u8..6,
        15u32..=300,
        any::<u64>(),
        prop::option::of(any::<u64>()),
        digits,
    );
    TestRunner::new(config(256)).run(&inputs, |(key, mix, period, time, step, code)| {
        let alg = [OtpAlg::Sha1, OtpAlg::Sha256, OtpAlg::Sha512]
            .get(usize::from(mix % 3))
            .copied()
            .ok_or_else(|| fail("alg"))?;
        let digits = if mix < 3 { Digits::Six } else { Digits::Eight };
        let skew = if time % 2 == 0 {
            Skew::One
        } else {
            Skew::Exact
        };
        let t = Totp::new(
            OtpKey::import(key).map_err(fail)?,
            alg,
            digits,
            Period::new(period).map_err(fail)?,
            skew,
        );
        let mut e = seeded(1);
        let row = step.and_then(|s| Record::decode(&[&[1, 1][..], &s.to_be_bytes()].concat()).ok());
        let held = row.as_ref().and_then(|r| match r {
            Record::TotpStep(s) => Some(Row::new(s, base::Version::new(1))),
            _ => None,
        });
        let permit = common::permit(None, UnixTime::new(time)).ok_or_else(|| fail("permit"))?;
        let verdict = t.verify(permit, &OtpCode::parse(&code).map_err(fail)?, held, &mut e);
        prop_assert!(verdict.is_ok());
        Ok(())
    })
}

#[test]
fn no_internal_recovery() -> Result<(), TestError<(u8, u64, bool)>> {
    TestRunner::new(config(64)).run(
        &(1u8..=16, any::<u64>(), any::<bool>()),
        |(n, seed, present)| {
            let mut e = seeded(seed);
            let pending =
                recovery_generate(RecoveryCount::new(n).map_err(fail)?, &mut e).map_err(fail)?;
            let mut store = Mem::new();
            let receipt =
                applied(&mut store, pending.effect(), NOW).ok_or_else(|| fail("apply"))?;
            let codes = pending.settle(receipt).map_err(fail)?;
            let code = codes.first().ok_or_else(|| fail("code"))?;
            let row = stored(&mut store, code.key());
            let hash = row
                .as_ref()
                .filter(|_| present)
                .and_then(|r| match r.record() {
                    Record::Recovery(h) => Some(Row::new(h, r.version())),
                    _ => None,
                });
            let permit = common::permit(None, NOW).ok_or_else(|| fail("permit"))?;
            prop_assert!(recovery_verify(permit, code, hash, &mut e).is_ok());
            Ok(())
        },
    )
}

#[test]
fn err_independent_of_secret() -> Result<(), Boxed> {
    let cost = factor::Cost::new(
        factor::Memory::kib(7_168),
        factor::Passes::new(5),
        factor::Lanes::new(1),
    )?;
    let new = factor::NewPassword::new("correct horse battery", factor::Minimum::SingleFactor)?;
    let stored = Phc::parse(factor::password_hash(&new, cost, &mut seeded(2))?.as_str())?;
    // right, wrong and unrelated presented passwords all return a verdict, never an error, and hold the count alone
    for presented in ["correct horse battery", "correct horse batterz", "x"] {
        let permit = common::permit(None, NOW).ok_or("permit")?;
        let pending = factor::password_verify(
            permit,
            &factor::Password::presented(presented)?,
            &stored,
            cost,
            &mut seeded(3),
        )?;
        assert_eq!(
            pending
                .effect()
                .guards()
                .map(|g| **g.key())
                .collect::<Vec<_>>(),
            [Key::Attempts]
        );
    }
    Ok(())
}
