//! An assertion case through the public API: credential stored, ceremony started, response parsed and finished, effects applied on a `MemStore`.
use std::collections::BTreeMap;

use base::{BrowserBinding, Effect, Entropy, Secret, Store, UnixTime};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use store::MemStore;
use testkit::vectors::{Outcome, Vector, run};
use webauthn_rp::{
    Allow, Assertion, AssertionVerification, AuthenticationCeremony, AuthenticationOptions,
    AuthenticationResponse, Counter, CounterPolicy, Credential, CredentialDescriptor, CredentialId,
    CrossOrigin, DisplayName, Error, Key, Origin, Record, RelyingParty, Requirement, RpId,
    SpecStep, Timeout, UserHandle,
};

use crate::browser::browser;
use crate::hex::{hex, hex_list, hex_opt};
use crate::refusal::Refusal;

#[derive(Deserialize)]
#[serde(untagged)]
enum Cross {
    Mode(String),
    Listed { top_origins: Vec<String> },
}

#[derive(Deserialize)]
struct Pair {
    stored: u32,
    seen: u32,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Count {
    Advanced(u32),
    Regressed { regressed: Pair },
}

#[derive(Deserialize)]
struct Expect {
    ok: bool,
    #[serde(flatten)]
    refusal: Refusal,
    user_verified: Option<bool>,
    counter: Option<Count>,
}

/// The refusals the carried exam-spike file does not state, by case id.
pub(crate) type Refusals = BTreeMap<String, Refusal>;

#[derive(Deserialize)]
struct Row {
    id: String,
    expect: Refusal,
}

// the oracle's `allow`: the listed credentials of an identified user, or any credential that carries its user handle
#[derive(Deserialize)]
#[serde(untagged)]
enum Allowed {
    Discoverable(String),
    Listed {
        #[serde(deserialize_with = "hex_list")]
        credentials: Vec<Vec<u8>>,
        #[serde(default, deserialize_with = "hex_opt")]
        identified_user: Option<Vec<u8>>,
    },
}

#[derive(Deserialize)]
struct Key2 {
    #[serde(deserialize_with = "hex")]
    x: Vec<u8>,
    #[serde(deserialize_with = "hex")]
    y: Vec<u8>,
}

#[derive(Deserialize)]
pub(crate) struct Case {
    id: String,
    #[serde(rename = "pub")]
    key: Key2,
    #[serde(deserialize_with = "hex")]
    authenticator_data: Vec<u8>,
    #[serde(deserialize_with = "hex")]
    client_data_json: Vec<u8>,
    #[serde(deserialize_with = "hex")]
    signature: Vec<u8>,
    rp_id: String,
    origin: String,
    challenge: String,
    user_verification: Option<String>,
    counter_policy: Option<String>,
    stored_counter: Option<u32>,
    stored_backup_eligible: Option<bool>,
    cross_origin: Option<Cross>,
    // the members below are those of the files that vary the allow list, the stored credential or the browser; a case without `allow` is identified by the fixed user and carries that user's handle
    #[serde(default, deserialize_with = "hex_opt")]
    raw_id: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "hex_opt")]
    stored_credential_id: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "hex_opt")]
    stored_user_handle: Option<Vec<u8>>,
    allow: Option<Allowed>,
    #[serde(default, deserialize_with = "hex_opt")]
    user_handle: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "hex_opt")]
    binding: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "hex_opt")]
    finish_binding: Option<Vec<u8>>,
    expect: Expect,
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
const ID: &[u8] = b"credential-id";
const USER: &[u8] = b"user-handle";

fn len4(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(bytes);
}

// the stored form of a credential: version 1, kind 2, ES256 key, UV initialized, no transports, no attestation; `backup` is 0 single device, 1 multi-device not backed up, 2 backed up
impl Case {
    fn stored_id(&self) -> &[u8] {
        self.stored_credential_id.as_deref().unwrap_or(ID)
    }

    fn stored_user(&self) -> &[u8] {
        self.stored_user_handle.as_deref().unwrap_or(USER)
    }
}

fn credential_record(case: &Case, sign_count: u32, backup: u8) -> Vec<u8> {
    let mut r = vec![1, 2];
    len4(&mut r, case.stored_id());
    r.push(0);
    r.extend_from_slice(&case.key.x);
    r.extend_from_slice(&case.key.y);
    r.extend_from_slice(&sign_count.to_be_bytes());
    r.extend_from_slice(&[0, 0, backup]);
    len4(&mut r, case.stored_user());
    r.extend_from_slice(&[0; 16]);
    r.extend_from_slice(&[0, 0, 1, 0, 0]);
    r
}

pub(crate) struct Flow {
    pub(crate) result: Result<Assertion, Error>,
    pub(crate) left: BTreeMap<Key, Record>,
    pub(crate) before: BTreeMap<Key, Record>,
    pub(crate) finished: bool,
}

// `Err` is a failure of this harness, never of the crate
fn flow(c: &Case, spike: bool) -> Result<Flow, &'static str> {
    let now = UnixTime::new(NOW);
    let mut ent = Fixed(
        base::b64url_decode(&c.challenge).map_err(|_| "challenge")?,
        testkit::seeded(1),
    );
    let tops = match &c.cross_origin {
        Some(Cross::Listed { top_origins }) => CrossOrigin::Listed(
            top_origins
                .iter()
                .filter_map(|o| Origin::parse(o).ok())
                .collect(),
        ),
        Some(Cross::Mode(mode)) if mode != "deny" => CrossOrigin::AnyTop,
        _ => CrossOrigin::Deny,
    };
    let policy = if c.counter_policy.as_deref() == Some("tolerate") {
        CounterPolicy::Tolerate
    } else {
        CounterPolicy::Reject
    };
    let name = DisplayName::parse("Example").map_err(|_| "name")?;
    let rp = RelyingParty::builder(
        RpId::parse(&c.rp_id).map_err(|_| "rp id")?,
        name,
        Origin::parse(&c.origin).map_err(|_| "origin")?,
        policy,
    )
    .cross_origin(tops)
    .build()
    .map_err(|_| "rp")?;
    let requirement = match c.user_verification.as_deref() {
        Some("required") => Requirement::Required,
        Some("discouraged") => Requirement::Discouraged,
        _ => Requirement::Preferred,
    };
    let eligible = c.stored_backup_eligible.unwrap_or(spike);
    let bytes = credential_record(c, c.stored_counter.unwrap_or(0), u8::from(eligible));
    let credential = Record::decode(&bytes).map_err(|_| "record")?;
    let id = CredentialId::from_bytes(c.stored_id()).map_err(|_| "id")?;
    let mut store: MemStore<Key, Record> = MemStore::default();
    let seed = Effect::created(
        &mut testkit::seeded(2),
        Key::Credential(id.clone()),
        credential,
        None,
    );
    store
        .apply(&seed, now)
        .map_err(|_| "seed")?
        .map_err(|_| "seed")?;
    let before = store.contents(now);
    let timeout = Timeout::from_secs(60).map_err(|_| "timeout")?;
    let (started_in, finished_in) = match (&c.binding, &c.finish_binding) {
        (Some(started), Some(finished)) => (browser(started)?, browser(finished)?),
        _ => (
            BrowserBinding::from(&Secret::new([5; 32])),
            BrowserBinding::from(&Secret::new([5; 32])),
        ),
    };
    let (user, listed, discoverable) = match &c.allow {
        None => (c.stored_user(), &[][..], false),
        Some(Allowed::Discoverable(mode)) => {
            if mode != "discoverable" {
                return Err("allow");
            }
            (c.stored_user(), &[][..], true)
        }
        Some(Allowed::Listed {
            credentials,
            identified_user,
        }) => (
            identified_user.as_deref().unwrap_or(c.stored_user()),
            credentials.as_slice(),
            false,
        ),
    };
    let user = UserHandle::from_stored(user).map_err(|_| "user")?;
    let listed = listed
        .iter()
        .map(|id| CredentialId::from_bytes(id).map(|id| CredentialDescriptor::new(id, &[])))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "allow")?;
    let allow = if discoverable {
        Allow::Discoverable
    } else {
        Allow::User {
            user: &user,
            credentials: &listed,
        }
    };
    let (_, start) = rp
        .start_authentication(
            allow,
            &AuthenticationOptions::new(requirement, timeout),
            &started_in,
            now,
            &mut ent,
        )
        .map_err(|_| "start")?;
    store
        .apply(&start, now)
        .map_err(|_| "start")?
        .map_err(|_| "start")?;
    let handle = if c.allow.is_some() {
        c.user_handle.as_deref()
    } else {
        Some(USER)
    };
    let response = AuthenticationResponse::new(
        c.raw_id.as_deref().unwrap_or(ID),
        &c.client_data_json,
        &c.authenticator_data,
        &c.signature,
        handle,
    );
    let response = match response {
        Ok(response) => response,
        Err(result) => {
            return Ok(Flow {
                result: Err(result),
                left: store.contents(now),
                before,
                finished: false,
            });
        }
    };
    // the started ceremony, as a host holding the session would load it, whatever challenge the response carries
    let started = Key::Ceremony(base::Digest::from_bytes(Sha256::digest(&ent.0).into()));
    // the host loads the credential it holds, which is the response's only when the host is right
    let held = Key::Credential(id);
    let rows = store
        .load(&[started.clone(), held.clone()], now)
        .map_err(|_| "load")?;
    let (Some(base::Slot::Row(ceremony)), Some(base::Slot::Row(stored))) =
        (rows.get(&started), rows.get(&held))
    else {
        return Err("rows");
    };
    let ceremony =
        AuthenticationCeremony::from_row(ceremony, |r| Some(r)).map_err(|_| "ceremony")?;
    let stored = Credential::from_row(stored, |r| Some(r)).map_err(|_| "stored")?;
    let verdict =
        rp.finish_authentication(ceremony, stored, &response, &finished_in, now, &mut ent);
    let receipt = store
        .apply(verdict.effect(), now)
        .map_err(|_| "apply")?
        .map_err(|_| "apply")?;
    let result = verdict.settle(receipt).map_err(|_| "settle")?;
    Ok(Flow {
        result,
        left: store.contents(now),
        before,
        finished: true,
    })
}

/// One case through the ceremony: ok or refused as the oracle says, the kind and step it states, and the effect it leaves.
pub(crate) fn check(c: &Case, spike: Option<&Refusals>) -> Outcome {
    let done = flow(c, spike.is_some());
    assert_eq!(done.as_ref().err(), None, "{}", c.id);
    let Ok(done) = done else {
        return Outcome::NotApplicable;
    };
    assert_eq!(
        done.result.is_ok(),
        c.expect.ok,
        "{} {:?}",
        c.id,
        done.result.as_ref().err()
    );
    let ceremonies = done
        .left
        .keys()
        .filter(|k| matches!(k, Key::Ceremony(_)))
        .count();
    assert_eq!(
        ceremonies,
        usize::from(!done.finished),
        "{}: the finish deletes the ceremony row",
        c.id
    );
    match &done.result {
        Ok(assertion) => {
            let verified = !matches!(
                assertion.user_verification(),
                AssertionVerification::PresenceOnly
            );
            assert!(
                c.expect.user_verified.is_none_or(|v| v == verified),
                "{}",
                c.id
            );
            let want = match c.expect.counter {
                Some(Count::Advanced(0)) => Counter::Unsupported,
                Some(Count::Advanced(n)) => Counter::Advanced(n),
                Some(Count::Regressed {
                    regressed: Pair { stored, seen },
                }) => Counter::Regressed { stored, seen },
                None => assertion.counter(),
            };
            assert_eq!(assertion.counter(), want, "{}", c.id);
            let flags = c.authenticator_data.get(32).copied().unwrap_or(0);
            let backup = if flags & 0x08 == 0 {
                0
            } else {
                1 + u8::from(flags & 0x10 != 0)
            };
            let count = match assertion.counter() {
                Counter::Advanced(n) => n,
                _ => c.stored_counter.unwrap_or(0),
            };
            let want = Record::decode(&credential_record(c, count, backup)).ok();
            let key = CredentialId::from_bytes(c.stored_id()).map(Key::Credential);
            assert_eq!(
                key.ok().and_then(|k| done.left.get(&k).cloned()),
                want,
                "{}: the credential row is updated",
                c.id
            );
        }
        Err(err) => {
            spike
                .and_then(|table| table.get(&c.id))
                .unwrap_or(&c.expect.refusal)
                .check(
                    &c.id,
                    Some(SpecStep::Authentication),
                    err.kind(),
                    err.spec_step(),
                );
            let credentials = |m: &BTreeMap<Key, Record>| {
                m.iter()
                    .filter(|(k, _)| matches!(k, Key::Credential(_)))
                    .map(|(_, r)| r.clone())
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                credentials(&done.left),
                credentials(&done.before),
                "{}: the credential row is untouched",
                c.id
            );
        }
    }
    Outcome::Checked
}

/// Every case of `vector` through the ceremony.
pub(crate) fn cases(vector: Vector, floor: usize, spike: bool) {
    // the carried exam-spike file states only ok, so our own table says what each of its refusals is
    let mut table = Refusals::new();
    let refusals = run::<Row>(
        testkit::vector!("webauthn-rp-derived/exam-spike-refusals.json"),
        7,
        |row| {
            table.insert(row.id.clone(), row.expect.clone());
            Outcome::Checked
        },
    );
    assert_eq!(refusals.checked(), refusals.total());
    let table = spike.then_some(&table);
    let tally = run::<Case>(vector, floor, |c| check(c, table));
    assert_eq!(tally.checked(), tally.total());
}
