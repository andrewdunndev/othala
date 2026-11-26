//! Row `roundtrip`: a virtual authenticator registers and authenticates through the public API, in a consumer's key and record types lifted from this crate's, applied on a `MemStore` and settled with its receipt (CONTRACT R143, R144).
//! The authenticator signs here; the crate never does. Only `none` attestation exists until webauthn-08, so `packed` self is not run.
use base::{
    BrowserBinding, Digest, Effect, Entropy, Row, Scope, Secret, Slot, Store, StoreKey, UnixTime,
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest as _, Sha256};
use store::MemStore;
use webauthn_rp::{
    Allow, Assertion, AssertionVerification, AuthenticationCeremony, AuthenticationOptions,
    AuthenticationResponse, Counter, CounterPolicy, Credential, CredentialId, DisplayName, Error,
    Key, Origin, Record, RegistrationCeremony, RegistrationOptions, RegistrationResponse,
    RelyingParty, Requirement, ResidentKey, RpId, Timeout, TrustDecision, TrustQuery, TrustSource,
    UserEntity, UserHandle, UserName,
};

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

struct Unknown;

impl TrustSource for Unknown {
    fn decide(&self, _: &TrustQuery<'_>) -> TrustDecision<'_> {
        TrustDecision::Unknown
    }
}

// the challenge first, then effect ids from a seeded source
struct Fixed(Vec<u8>, testkit::Seeded);

impl Entropy for Fixed {
    fn fill(&mut self, out: &mut [u8]) {
        if out.len() == self.0.len() {
            out.copy_from_slice(&self.0);
        } else {
            self.1.fill(out);
        }
    }
}

const NOW: u64 = 1_000;
const ID: &[u8] = b"virtual-credential";
const USER: &[u8] = b"user-handle";

type Consumer = MemStore<AppKey, AppRecord>;

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn client_data(kind: &str, challenge: &[u8]) -> Vec<u8> {
    format!(
        r#"{{"type":"{kind}","challenge":"{}","origin":"https://example.org"}}"#,
        base::b64url_encode(challenge)
    )
    .into_bytes()
}

// the authenticator: an ES256 key, a counter and the data it signs
struct Virtual {
    key: SigningKey,
    count: u32,
}

impl Virtual {
    fn cose(&self) -> Result<Vec<u8>, &'static str> {
        let point = self.key.verifying_key().to_sec1_point(false);
        let (x, y) = (point.x().ok_or("x")?, point.y().ok_or("y")?);
        Ok([
            &[0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20][..],
            x,
            &[0x22, 0x58, 0x20],
            y,
        ]
        .concat())
    }

    // `none` attestation (L3 8.7): the three members of the attestation object around the attested authenticator data
    fn create(&self, challenge: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        let data = [
            &sha(b"example.org")[..],
            &[0x45],
            &self.count.to_be_bytes(),
            &[7; 16],
            &[0, u8::try_from(ID.len()).map_err(|_| "id")?],
            ID,
            &self.cose()?,
        ]
        .concat();
        let object = [
            &[0xa3, 0x63][..],
            b"fmt",
            &[0x64],
            b"none",
            &[0x67],
            b"attStmt",
            &[0xa0, 0x68],
            b"authData",
            &[0x58, u8::try_from(data.len()).map_err(|_| "data")?],
            &data,
        ]
        .concat();
        Ok((client_data("webauthn.create", challenge), object))
    }

    fn get(&mut self, challenge: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        self.count += 1;
        let data = [&sha(b"example.org")[..], &[0x05], &self.count.to_be_bytes()].concat();
        let json = client_data("webauthn.get", challenge);
        let signature: Signature = self.key.sign(&[data.as_slice(), &sha(&json)].concat());
        (json, data, signature.to_der().as_bytes().to_vec())
    }
}

fn rp() -> Result<RelyingParty, &'static str> {
    let name = DisplayName::parse("Example").map_err(|_| "name")?;
    let origin = Origin::parse("https://example.org").map_err(|_| "origin")?;
    RelyingParty::builder(
        RpId::parse("example.org").map_err(|_| "rp id")?,
        name,
        origin,
        CounterPolicy::Reject,
    )
    .build()
    .map_err(|_| "rp")
}

fn binding() -> BrowserBinding {
    BrowserBinding::from(&Secret::new([5; 32]))
}

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
