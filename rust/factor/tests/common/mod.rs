//! One TOTP case run end to end: seed the stored last step, issue a permit, verify, apply the effect, settle.
#![allow(dead_code, reason = "each row uses part of this")]
use base::{Effect, Row, Slot, Store, UnixTime};
use factor::{
    Attempts, Digits, ErrorKind, Key, OtpAlg, OtpCode, OtpKey, OtpMatch, Period, Record, Rejected,
    Skew, Throttle, Totp,
};
use serde::Deserialize;
use testkit::{MemStore, Seeded, seeded};

pub(crate) type Mem = MemStore<Key, Record>;

#[derive(Clone, Deserialize)]
pub(crate) struct Case {
    pub(crate) id: String,
    pub(crate) secret: String,
    pub(crate) alg: String,
    pub(crate) digits: u8,
    pub(crate) step: u32,
    pub(crate) time: u64,
    pub(crate) window: u8,
    pub(crate) last_step: Option<u64>,
    pub(crate) code: String,
    pub(crate) expect: Expect,
}

#[derive(Clone, Deserialize)]
pub(crate) struct Expect {
    pub(crate) ok: bool,
    pub(crate) step: Option<u64>,
    pub(crate) kind: Option<String>,
}

pub(crate) fn unhex(text: &str) -> Option<Vec<u8>> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

pub(crate) fn totp(c: &Case) -> Option<Totp> {
    let alg = match c.alg.as_str() {
        "sha1" => OtpAlg::Sha1,
        "sha256" => OtpAlg::Sha256,
        "sha512" => OtpAlg::Sha512,
        _ => return None,
    };
    let digits = if c.digits == 6 {
        Digits::Six
    } else {
        Digits::Eight
    };
    let skew = if c.window == 0 {
        Skew::Exact
    } else {
        Skew::One
    };
    let key = OtpKey::import(unhex(&c.secret)?).ok()?;
    Some(Totp::new(key, alg, digits, Period::new(c.step).ok()?, skew))
}

/// The row `Record::decode` reads for `step` under R5's layout.
pub(crate) fn step_record(step: u64) -> Option<Record> {
    Record::decode(&[&[1, 1][..], &step.to_be_bytes()].concat()).ok()
}

pub(crate) fn applied(
    store: &mut Mem,
    effect: &Effect<Key, Record>,
    now: UnixTime,
) -> Option<base::Receipt> {
    store.apply(effect, now).ok()?.ok()
}

pub(crate) fn seed_step(store: &mut Mem, e: &mut Seeded, step: u64) -> Option<()> {
    let effect = Effect::created(e, Key::TotpStep, step_record(step)?, None);
    applied(store, &effect, UnixTime::new(0)).map(drop)
}

pub(crate) fn stored(store: &mut Mem, key: Key) -> Option<Row<Record>> {
    let rows = store.load(&[key], UnixTime::new(0)).ok()?;
    match rows.get(&key)? {
        Slot::Row(r) => Some(Row::new(r.record().clone(), r.version())),
        _ => None,
    }
}

pub(crate) fn last(store: &mut Mem) -> Option<Row<factor::TotpStep>> {
    let row = stored(store, Key::TotpStep)?;
    match row.record() {
        Record::TotpStep(s) => Some(Row::new(*s, row.version())),
        _ => None,
    }
}

pub(crate) fn attempts(store: &mut Mem) -> Option<Vec<u8>> {
    stored(store, Key::Attempts).map(|r| r.record().encode())
}

pub(crate) fn attempts_row(store: &mut Mem) -> Option<Row<Attempts>> {
    let row = stored(store, Key::Attempts)?;
    match row.record() {
        Record::Attempts(a) => Some(Row::new(*a, row.version())),
        _ => None,
    }
}

/// The stored count, read from the row's encoding (R5: bytes 2 to 5, big-endian).
pub(crate) fn count(store: &mut Mem) -> Option<u32> {
    let bytes = stored(store, Key::Attempts)?.record().encode();
    bytes.get(2..6)?.try_into().ok().map(u32::from_be_bytes)
}

pub(crate) fn seen<T>(row: &Row<T>) -> Row<&T> {
    Row::new(row.record(), row.version())
}

/// One verdict as a host runs it: read the rows, check, verify, apply, settle.
pub(crate) fn verify_once(
    store: &mut Mem,
    e: &mut Seeded,
    totp: &Totp,
    code: &OtpCode,
    now: UnixTime,
) -> Option<Result<OtpMatch, Rejected>> {
    let (attempts, step) = (attempts_row(store), last(store));
    let permit = Throttle::unlimited()
        .check(attempts.as_ref().map(seen), now)
        .ok()?;
    let pending = totp.verify(permit, code, step.as_ref().map(seen), e).ok()?;
    let receipt = applied(store, pending.effect(), now)?;
    pending.settle(receipt).ok()
}

/// The rows of the RFC 6238 file, for tests that need codes known to be right.
pub(crate) fn rfc6238() -> Vec<Case> {
    let mut cases = Vec::new();
    testkit::vectors::run(testkit::vector!("rfc6238/totp.json"), 1, |c: &Case| {
        cases.push(c.clone());
        testkit::vectors::Outcome::Checked
    });
    cases
}

pub(crate) enum Outcome {
    Unparsed(ErrorKind),
    Verdict(Result<OtpMatch, Rejected>),
}

/// The case's outcome and the store after it.
pub(crate) fn run(c: &Case) -> Option<(Outcome, Mem)> {
    let (mut store, mut e) = (Mem::new(), seeded(1));
    if let Some(step) = c.last_step {
        seed_step(&mut store, &mut e, step)?;
    }
    let Ok(code) = OtpCode::parse(&c.code) else {
        return OtpCode::parse(&c.code)
            .err()
            .map(|err| (Outcome::Unparsed(err.kind()), store));
    };
    let verdict = verify_once(&mut store, &mut e, &totp(c)?, &code, UnixTime::new(c.time))?;
    Some((Outcome::Verdict(verdict), store))
}
