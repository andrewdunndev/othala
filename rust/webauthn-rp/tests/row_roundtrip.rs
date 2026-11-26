//! Row `roundtrip`: a virtual authenticator registers and authenticates through the public API, in a consumer's key and record types lifted from this crate's, applied on a `MemStore` and settled with its receipt (CONTRACT R143, R144).
//! The authenticator signs here; the crate never does. Only `none` attestation exists until webauthn-08, so `packed` self is not run.
use base::{Digest, Effect, Row, Scope, Slot, Store, StoreKey, UnixTime};
use p256::ecdsa::SigningKey;
use store::MemStore;
use webauthn_rp::{
    Allow, Assertion, AssertionVerification, AuthenticationCeremony, AuthenticationOptions,
    AuthenticationResponse, Counter, Credential, CredentialId, DisplayName, Error, Key, Record,
    RegistrationCeremony, RegistrationOptions, RegistrationResponse, Requirement, ResidentKey,
    Timeout, UserEntity, UserHandle, UserName,
};

#[path = "support/rig.rs"]
mod rig;
use rig::{Fixed, ID, NOW, USER, Unknown, Virtual, binding, client_data, rp, sha};

// a consumer's own key and record types, with this crate's inside
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum AppKey {
    Passkey(Key),
}

#[derive(Clone, Debug, PartialEq)]
enum AppRecord {
    Passkey(Record),
}

impl StoreKey for AppKey {
    fn scope(&self) -> Scope {
        let Self::Passkey(key) = self;
        key.scope()
    }
}

fn passkey(record: &AppRecord) -> Option<&Record> {
    let AppRecord::Passkey(record) = record;
    Some(record)
}

type Consumer = MemStore<AppKey, AppRecord>;

fn apply(
    store: &mut Consumer,
    effect: &Effect<AppKey, AppRecord>,
) -> Result<base::Receipt, &'static str> {
    store
        .apply(effect, UnixTime::new(NOW))
        .map_err(|_| "apply")?
        .map_err(|_| "conflict")
}

fn row<T>(
    store: &mut Consumer,
    key: &Key,
    narrow: impl Fn(&Row<AppRecord>) -> Result<Row<T>, Error>,
) -> Result<Row<T>, &'static str> {
    let key = AppKey::Passkey(key.clone());
    let rows = store
        .load(core::slice::from_ref(&key), UnixTime::new(NOW))
        .map_err(|_| "load")?;
    let Some(Slot::Row(found)) = rows.get(&key) else {
        return Err("row");
    };
    narrow(found).map_err(|_| "narrow")
}

fn register(
    store: &mut Consumer,
    who: &Virtual,
    challenge: &[u8],
    flip: Option<usize>,
) -> Result<Result<(), Error>, &'static str> {
    let now = UnixTime::new(NOW);
    let mut ent = Fixed(challenge.to_vec(), testkit::seeded(1));
    let entity = UserEntity::new(
        UserHandle::from_stored(USER).map_err(|_| "handle")?,
        UserName::parse("ada").map_err(|_| "user")?,
        DisplayName::parse("Ada").map_err(|_| "display")?,
    );
    let options = RegistrationOptions::new(
        Requirement::Preferred,
        ResidentKey::Preferred,
        Timeout::from_secs(60).map_err(|_| "timeout")?,
    );
    let rp = rp()?;
    let (_, start) = rp
        .start_registration(&entity, &[], &options, &binding(), now, &mut ent)
        .map_err(|_| "start")?;
    apply(
        store,
        &start
            .lift(AppKey::Passkey, AppRecord::Passkey)
            .map_err(|_| "lift")?,
    )?;
    let (mut json, object) = who.create(challenge)?;
    if let Some(b) = flip.and_then(|at| json.get_mut(at)) {
        *b ^= 1;
    }
    let response = match RegistrationResponse::new(ID, &json, &object, &[]) {
        Ok(response) => response,
        Err(e) => return Ok(Err(e)),
    };
    let started = Key::Ceremony(Digest::from_bytes(sha(challenge)));
    let state = row(store, &started, |r| {
        RegistrationCeremony::from_row(r, passkey)
    })?;
    let verdict = rp
        .finish_registration(state, &response, &binding(), &Unknown, now, &mut ent)
        .lift(AppKey::Passkey, AppRecord::Passkey)
        .map_err(|_| "lift")?;
    let receipt = apply(store, verdict.effect())?;
    Ok(verdict.settle(receipt).map_err(|_| "settle")?.map(|_| ()))
}

fn login(
    store: &mut Consumer,
    who: &mut Virtual,
    challenge: &[u8],
    flip: Option<(usize, usize)>,
) -> Result<Result<Assertion, Error>, &'static str> {
    let now = UnixTime::new(NOW);
    let mut ent = Fixed(
        challenge.to_vec(),
        testkit::seeded(100 + u64::from(challenge.first().copied().unwrap_or(0))),
    );
    let user = UserHandle::from_stored(USER).map_err(|_| "handle")?;
    let options = AuthenticationOptions::new(
        Requirement::Preferred,
        Timeout::from_secs(60).map_err(|_| "timeout")?,
    );
    let rp = rp()?;
    let (_, start) = rp
        .start_authentication(
            Allow::User {
                user: &user,
                credentials: &[],
            },
            &options,
            &binding(),
            now,
            &mut ent,
        )
        .map_err(|_| "start")?;
    apply(
        store,
        &start
            .lift(AppKey::Passkey, AppRecord::Passkey)
            .map_err(|_| "lift")?,
    )?;
    let (json, data, signature) = who.get(challenge);
    let mut parts = [json, data, signature];
    if let Some(b) = flip.and_then(|(part, at)| parts.get_mut(part)?.get_mut(at)) {
        *b ^= 1;
    }
    let [json, data, signature] = parts;
    let response = match AuthenticationResponse::new(ID, &json, &data, &signature, Some(USER)) {
        Ok(response) => response,
        Err(e) => return Ok(Err(e)),
    };
    let id = CredentialId::from_bytes(ID).map_err(|_| "id")?;
    let state = row(
        store,
        &Key::Ceremony(Digest::from_bytes(sha(challenge))),
        |r| AuthenticationCeremony::from_row(r, passkey),
    )?;
    let stored = row(store, &Key::Credential(id), |r| {
        Credential::from_row(r, passkey)
    })?;
    let verdict = rp
        .finish_authentication(state, stored, &response, &binding(), now, &mut ent)
        .lift(AppKey::Passkey, AppRecord::Passkey)
        .map_err(|_| "lift")?;
    let receipt = apply(store, verdict.effect())?;
    verdict.settle(receipt).map_err(|_| "settle")
}

fn who() -> Result<Virtual, &'static str> {
    Ok(Virtual {
        key: SigningKey::from_slice(&[3; 32]).map_err(|_| "key")?,
        count: 0,
    })
}

#[test]
fn a_registered_credential_authenticates_with_an_advancing_counter() {
    let mut store = Consumer::default();
    let mut authenticator = who().ok();
    let registered = authenticator
        .as_ref()
        .map(|a| register(&mut store, a, &[1; 32], None));
    assert_eq!(registered, Some(Ok(Ok(()))));
    let Some(authenticator) = authenticator.as_mut() else {
        return;
    };
    for round in 1..=3u8 {
        let done = login(&mut store, authenticator, &[10 + round; 32], None);
        let counter = done
            .ok()
            .and_then(Result::ok)
            .map(|a| (a.counter(), a.user_verification()));
        assert_eq!(
            counter,
            Some((
                Counter::Advanced(u32::from(round)),
                AssertionVerification::Verified
            )),
            "round {round}"
        );
    }
}

#[test]
fn any_one_byte_change_to_a_response_fails() {
    let Ok(authenticator) = who() else {
        return;
    };
    let length = client_data("webauthn.create", &[1; 32]).len();
    for at in 0..length {
        let mut store = Consumer::default();
        let done = register(&mut store, &authenticator, &[1; 32], Some(at));
        assert!(
            matches!(done, Ok(Err(_))),
            "registration byte {at}: {done:?}"
        );
    }
    let mut store = Consumer::default();
    assert_eq!(
        register(&mut store, &authenticator, &[1; 32], None),
        Ok(Ok(()))
    );
    let signed = Virtual {
        key: authenticator.key.clone(),
        count: 0,
    }
    .get(&[2; 32]);
    for (part, size) in [signed.0.len(), signed.1.len(), signed.2.len()]
        .into_iter()
        .enumerate()
    {
        for at in 0..size {
            let mut copy = store.clone();
            let mut again = Virtual {
                key: authenticator.key.clone(),
                count: 0,
            };
            let done = login(&mut copy, &mut again, &[2; 32], Some((part, at)));
            assert!(
                matches!(done, Ok(Err(_))),
                "part {part} byte {at}: {done:?}"
            );
        }
    }
}
