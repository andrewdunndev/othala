//! Row `race`: ceremony once, credential once, counter and deadline, with every decision taken against one snapshot and its effect applied in every order (CONTRACT O2 to O4, R56, R85).
//! `testkit::race` takes an owned `Effect` and a verdict's is reachable only by reference, so the snapshot-race loop is written out here with the same shape.
use std::collections::BTreeMap;

use base::{Conflict, Digest, Failure, Slot, Store, UnixTime};
use p256::ecdsa::SigningKey;
use store::MemStore;
use webauthn_rp::{
    Allow, Assertion, AuthenticationCeremony, AuthenticationOptions, AuthenticationResponse,
    Credential, CredentialId, DisplayName, Error, ErrorKind, Key, Record, Registered,
    RegistrationCeremony, RegistrationOptions, RegistrationResponse, Requirement, ResidentKey,
    Timeout, UserEntity, UserHandle, UserName, Verdict,
};

#[path = "support/rig.rs"]
mod rig;
use rig::{Fixed, ID, NOW, USER, Unknown, Virtual, binding, rp, sha};

type Store2 = MemStore<Key, Record>;
type Setup<T> = Result<T, &'static str>;
type Decision<'a, T> = &'a dyn Fn(&Store2) -> Setup<Verdict<T>>;
type Outcome<T> = (usize, Result<Result<T, Error>, Conflict<Key>>);

fn at(secs: u64) -> UnixTime {
    UnixTime::new(secs)
}

fn authenticator(count: u32) -> Setup<Virtual> {
    Ok(Virtual {
        key: SigningKey::from_slice(&[3; 32]).map_err(|_| "key")?,
        count,
    })
}

fn key_of(challenge: u8) -> Key {
    Key::Ceremony(Digest::from_bytes(sha(&[challenge; 32])))
}

fn credential() -> Setup<Key> {
    CredentialId::from_bytes(ID)
        .map(Key::Credential)
        .map_err(|_| "id")
}

fn apply(store: &mut Store2, effect: &base::Effect<Key, Record>) -> Setup<base::Receipt> {
    store
        .apply(effect, at(NOW))
        .map_err(|_| "fault")?
        .map_err(|_| "conflict")
}

fn begin_registration(store: &mut Store2, challenge: u8) -> Setup<()> {
    let mut ent = Fixed(vec![challenge; 32], testkit::seeded(u64::from(challenge)));
    let user = UserEntity::new(
        UserHandle::from_stored(USER).map_err(|_| "handle")?,
        UserName::parse("ada").map_err(|_| "user")?,
        DisplayName::parse("Ada").map_err(|_| "display")?,
    );
    let options = RegistrationOptions::new(
        Requirement::Preferred,
        ResidentKey::Preferred,
        Timeout::from_secs(60).map_err(|_| "timeout")?,
    );
    let (_, start) = rp()?
        .start_registration(&user, &[], &options, &binding(), at(NOW), &mut ent)
        .map_err(|_| "start")?;
    apply(store, &start).map(|_| ())
}

fn begin_login(store: &mut Store2, challenge: u8) -> Setup<()> {
    let mut ent = Fixed(vec![challenge; 32], testkit::seeded(u64::from(challenge)));
    let user = UserHandle::from_stored(USER).map_err(|_| "handle")?;
    let options = AuthenticationOptions::new(
        Requirement::Preferred,
        Timeout::from_secs(60).map_err(|_| "timeout")?,
    );
    let (_, start) = rp()?
        .start_authentication(
            Allow::User {
                user: &user,
                credentials: &[],
            },
            &options,
            &binding(),
            at(NOW),
            &mut ent,
        )
        .map_err(|_| "start")?;
    apply(store, &start).map(|_| ())
}

fn loaded<T>(
    store: &Store2,
    key: &Key,
    narrow: impl Fn(&base::Row<Record>) -> Result<base::Row<T>, Error>,
) -> Setup<base::Row<T>> {
    let rows = store
        .clone()
        .load(core::slice::from_ref(key), at(NOW))
        .map_err(|_| "load")?;
    let Some(Slot::Row(row)) = rows.get(key) else {
        return Err("row");
    };
    narrow(row).map_err(|_| "narrow")
}

// a finish of the registration `challenge` begun, decided at `now` from the rows as they stand in `store`
fn finish_registration(
    store: &Store2,
    challenge: u8,
    effect_seed: u64,
    now: u64,
) -> Setup<Verdict<Registered>> {
    let (json, object) = authenticator(0)?.create(&[challenge; 32])?;
    let response = RegistrationResponse::new(ID, &json, &object, &[]).map_err(|_| "response")?;
    let state = loaded(store, &key_of(challenge), |r| {
        RegistrationCeremony::from_row(r, |r| Some(r))
    })?;
    let mut ent = Fixed(vec![challenge; 32], testkit::seeded(effect_seed));
    Ok(rp()?.finish_registration(state, &response, &binding(), &Unknown, at(now), &mut ent))
}

// a finish of the login `challenge` begun, carrying the authenticator's `count`
fn finish_login(
    store: &Store2,
    challenge: u8,
    count: u32,
    effect_seed: u64,
    now: u64,
) -> Setup<Verdict<Assertion>> {
    let (json, data, signature) = authenticator(count - 1)?.get(&[challenge; 32]);
    let response = AuthenticationResponse::new(ID, &json, &data, &signature, Some(USER))
        .map_err(|_| "response")?;
    let state = loaded(store, &key_of(challenge), |r| {
        AuthenticationCeremony::from_row(r, |r| Some(r))
    })?;
    let stored = loaded(store, &credential()?, |r| {
        Credential::from_row(r, |r| Some(r))
    })?;
    let mut ent = Fixed(vec![challenge; 32], testkit::seeded(effect_seed));
    Ok(rp()?.finish_authentication(state, stored, &response, &binding(), at(now), &mut ent))
}

struct Run<T> {
    order: Vec<usize>,
    outcomes: Vec<Outcome<T>>,
    store: Store2,
}

fn permutations(n: usize) -> Vec<Vec<usize>> {
    if n == 0 {
        return vec![vec![]];
    }
    (0..n)
        .flat_map(|first| {
            let rest: Vec<usize> = (0..n).filter(|i| *i != first).collect();
            permutations(n - 1).into_iter().map(move |p| {
                [
                    vec![first],
                    p.iter().filter_map(|i| rest.get(*i).copied()).collect(),
                ]
                .concat()
            })
        })
        .collect()
}

// each op decides against `start`; its effect is then applied in every order on its own copy of `start`
fn race<T>(start: &Store2, ops: &[Decision<'_, T>]) -> Setup<Vec<Run<T>>> {
    let mut runs = Vec::new();
    for order in permutations(ops.len()) {
        let mut store = start.clone();
        let mut verdicts = Vec::new();
        for op in ops {
            verdicts.push(Some(op(start)?));
        }
        let mut outcomes = Vec::new();
        for &i in &order {
            let verdict = verdicts
                .get_mut(i)
                .and_then(Option::take)
                .ok_or("verdict")?;
            match store
                .apply(verdict.effect(), at(NOW))
                .map_err(|_| "fault")?
            {
                Ok(receipt) => {
                    outcomes.push((i, Ok(verdict.settle(receipt).map_err(|_| "settle")?)))
                }
                Err(conflict) => outcomes.push((i, Err(conflict))),
            }
        }
        runs.push(Run {
            order,
            outcomes,
            store,
        });
    }
    Ok(runs)
}

fn failed(c: &Conflict<Key>) -> Vec<(Key, Failure)> {
    c.failures().to_vec()
}

fn contents(store: &Store2) -> BTreeMap<Key, Record> {
    store.contents(at(NOW))
}

fn sign_count(store: &Store2) -> Option<u32> {
    match contents(store).get(&credential().ok()?)? {
        Record::Credential(c) => Some(c.sign_count()),
        _ => None,
    }
}

fn wins<T>(run: &Run<T>) -> Vec<usize> {
    run.outcomes
        .iter()
        .filter_map(|(i, o)| o.as_ref().ok().map(|_| *i))
        .collect()
}

#[test]
fn a_ceremony_finishes_once_whatever_the_order() -> Setup<()> {
    let mut start = Store2::default();
    begin_registration(&mut start, 1)?;
    let (a, b) = (
        |s: &Store2| finish_registration(s, 1, 50, NOW + 1),
        |s: &Store2| finish_registration(s, 1, 51, NOW + 1),
    );
    let runs = race(&start, &[&a, &b])?;
    assert_eq!(runs.len(), 2);
    for run in &runs {
        assert_eq!(wins(run).len(), 1, "order {:?}: one registers", run.order);
        let loser = run
            .outcomes
            .iter()
            .find_map(|(_, o)| o.as_ref().err())
            .ok_or("loser")?;
        assert!(
            failed(loser).contains(&(key_of(1), Failure::Missing)),
            "the loser met the deleted ceremony row: {:?}",
            failed(loser)
        );
        assert_eq!(
            contents(&run.store).keys().cloned().collect::<Vec<_>>(),
            vec![credential()?],
            "the credential alone is left"
        );
    }
    Ok(())
}

#[test]
fn a_credential_id_registers_once_across_ceremonies() -> Setup<()> {
    let mut start = Store2::default();
    begin_registration(&mut start, 1)?;
    begin_registration(&mut start, 2)?;
    let (a, b) = (
        |s: &Store2| finish_registration(s, 1, 50, NOW + 1),
        |s: &Store2| finish_registration(s, 2, 51, NOW + 1),
    );
    for run in race(&start, &[&a, &b])? {
        let [winner] = wins(&run)[..] else {
            return Err("one winner");
        };
        let loser = run
            .outcomes
            .iter()
            .find_map(|(_, o)| o.as_ref().err())
            .ok_or("loser")?;
        assert_eq!(
            failed(loser),
            vec![(credential()?, Failure::Present)],
            "order {:?}",
            run.order
        );
        let left = contents(&run.store);
        assert_eq!(
            left.keys().cloned().collect::<Vec<_>>().len(),
            2,
            "the credential and the loser's ceremony"
        );
        let (kept, gone) = if winner == 0 { (2, 1) } else { (1, 2) };
        assert!(
            left.contains_key(&key_of(kept)) && !left.contains_key(&key_of(gone)),
            "the loser's ceremony stays, the winner's is gone"
        );
        // deciding again from what is now stored loses the same way: the id is taken
        let again = finish_registration(&run.store, if winner == 0 { 2 } else { 1 }, 60, NOW + 1)?;
        let mut store = run.store.clone();
        let conflict = store
            .apply(again.effect(), at(NOW))
            .map_err(|_| "fault")?
            .err()
            .ok_or("conflict")?;
        assert_eq!(failed(&conflict), vec![(credential()?, Failure::Present)]);
    }
    Ok(())
}

#[test]
fn a_stale_counter_never_overwrites_a_newer_one() -> Setup<()> {
    let mut start = Store2::default();
    begin_registration(&mut start, 1)?;
    let registered = finish_registration(&start, 1, 50, NOW + 1)?;
    let receipt = apply(&mut start, registered.effect())?;
    registered
        .settle(receipt)
        .map_err(|_| "settle")?
        .map_err(|_| "registered")?;
    begin_login(&mut start, 2)?;
    begin_login(&mut start, 3)?;
    let (a, b) = (
        |s: &Store2| finish_login(s, 2, 1, 70, NOW + 1),
        |s: &Store2| finish_login(s, 3, 2, 71, NOW + 1),
    );
    for run in race(&start, &[&a, &b])? {
        assert_eq!(wins(&run).len(), 1, "order {:?}", run.order);
        let loser = run
            .outcomes
            .iter()
            .find_map(|(_, o)| o.as_ref().err())
            .ok_or("loser")?;
        assert_eq!(
            failed(loser),
            vec![(credential()?, Failure::Changed)],
            "the loser read the credential before the winner wrote it"
        );
        let first = sign_count(&run.store);
        // the loser decides again from the stored row: the older count is refused, the newer one advances
        let (challenge, count) = if wins(&run) == [0] { (3, 2) } else { (2, 1) };
        let again = finish_login(&run.store, challenge, count, 80, NOW + 1)?;
        let mut store = run.store.clone();
        let receipt = store
            .apply(again.effect(), at(NOW))
            .map_err(|_| "fault")?
            .map_err(|_| "conflict")?;
        let verdict = again.settle(receipt).map_err(|_| "settle")?;
        assert_eq!(
            verdict.as_ref().err().map(Error::kind),
            (count == 1).then_some(ErrorKind::CounterRegressed),
            "order {:?}",
            run.order
        );
        assert_eq!(
            sign_count(&store),
            Some(2),
            "order {:?}: the count ends at the newest, from {first:?}",
            run.order
        );
        assert!(first <= sign_count(&store));
    }
    Ok(())
}

#[test]
fn an_assertion_replays_once() -> Setup<()> {
    let mut start = Store2::default();
    begin_registration(&mut start, 1)?;
    let registered = finish_registration(&start, 1, 50, NOW + 1)?;
    let receipt = apply(&mut start, registered.effect())?;
    registered
        .settle(receipt)
        .map_err(|_| "settle")?
        .map_err(|_| "registered")?;
    begin_login(&mut start, 2)?;
    let (a, b) = (
        |s: &Store2| finish_login(s, 2, 1, 70, NOW + 1),
        |s: &Store2| finish_login(s, 2, 1, 71, NOW + 1),
    );
    for run in race(&start, &[&a, &b])? {
        assert_eq!(wins(&run).len(), 1, "order {:?}", run.order);
        assert_eq!(sign_count(&run.store), Some(1));
        let loser = run
            .outcomes
            .iter()
            .find_map(|(_, o)| o.as_ref().err())
            .ok_or("loser")?;
        assert!(failed(loser).contains(&(key_of(2), Failure::Missing)));
        assert_eq!(
            finish_login(&run.store, 2, 1, 90, NOW + 1).err(),
            Some("row"),
            "the consumed ceremony row cannot be loaded again"
        );
    }
    Ok(())
}

#[test]
fn the_deadline_is_the_records_not_the_stores() -> Setup<()> {
    let mut start = Store2::default();
    begin_registration(&mut start, 1)?;
    let deadline = NOW + 60;
    let (late, timely) = (
        |s: &Store2| finish_registration(s, 1, 50, deadline),
        |s: &Store2| finish_registration(s, 1, 51, deadline - 1),
    );
    for run in race(&start, &[&late, &timely])? {
        let verdicts: Vec<_> = run
            .outcomes
            .iter()
            .map(|(i, o)| {
                (
                    *i,
                    o.as_ref().ok().map(|v| v.as_ref().err().map(Error::kind)),
                )
            })
            .collect();
        let first = run.order.first().copied();
        assert_eq!(
            wins(&run),
            first.into_iter().collect::<Vec<_>>(),
            "{verdicts:?}"
        );
        // the late finish is refused as `Expired` even though the store still held the row it read
        let late_won = first == Some(0);
        assert_eq!(
            late_won,
            verdicts
                .iter()
                .any(|(i, v)| *i == 0 && *v == Some(Some(ErrorKind::Expired))),
            "{verdicts:?}"
        );
        assert_eq!(
            contents(&run.store).keys().cloned().collect::<Vec<_>>(),
            if late_won {
                vec![]
            } else {
                vec![credential()?]
            }
        );
    }
    Ok(())
}
