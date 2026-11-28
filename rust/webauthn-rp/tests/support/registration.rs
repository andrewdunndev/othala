//! The oracle's registration cases through start, parse and finish.
use serde::Deserialize;
use store::MemStore;
use testkit::vectors::{Outcome, Vector, run};
use webauthn_rp::{
    CoseAlgorithm, CredentialId, CrossOrigin, Key, Origin, Record, Requirement, SpecStep,
};

use crate::browser::browser;
use crate::ceremony::{Registration, register, relying_party};
use crate::hex::{hex, hex_opt};
use crate::refusal::Refusal;

#[derive(Deserialize)]
#[serde(untagged)]
enum Cross {
    Mode(String),
    Listed { top_origins: Vec<String> },
}

#[derive(Deserialize)]
struct Point {
    #[serde(deserialize_with = "hex")]
    x: Vec<u8>,
    #[serde(deserialize_with = "hex")]
    y: Vec<u8>,
}

#[derive(Deserialize)]
struct Expect {
    ok: bool,
    #[serde(flatten)]
    refusal: Refusal,
    user_verified: Option<bool>,
    #[serde(default, deserialize_with = "hex")]
    credential_id: Vec<u8>,
    public_key: Option<Point>,
}

#[derive(Deserialize)]
pub(crate) struct Case {
    id: String,
    #[serde(deserialize_with = "hex")]
    attestation_object: Vec<u8>,
    #[serde(deserialize_with = "hex")]
    client_data_json: Vec<u8>,
    rp_id: String,
    origin: String,
    challenge: String,
    user_verification: String,
    pub_key_cred_params: Vec<i64>,
    cross_origin: Cross,
    #[serde(default, deserialize_with = "hex_opt")]
    raw_id: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "hex_opt")]
    binding: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "hex_opt")]
    finish_binding: Option<Vec<u8>>,
    expect: Expect,
}

fn algorithm(cose: i64) -> Option<CoseAlgorithm> {
    match cose {
        -7 => Some(CoseAlgorithm::Es256),
        -35 => Some(CoseAlgorithm::Es384),
        -8 => Some(CoseAlgorithm::EdDsa),
        -257 => Some(CoseAlgorithm::Rs256),
        _ => None,
    }
}

/// One case through the ceremony: ok or refused as the oracle says, the kind and step it states, and the rows it leaves.
pub(crate) fn check(c: &Case) -> Outcome {
    let cross = match &c.cross_origin {
        Cross::Listed { top_origins } => CrossOrigin::Listed(
            top_origins
                .iter()
                .filter_map(|o| Origin::parse(o).ok())
                .collect(),
        ),
        Cross::Mode(_) => CrossOrigin::Deny,
    };
    let requirement = if c.user_verification == "required" {
        Requirement::Required
    } else {
        Requirement::Preferred
    };
    let algorithms: Vec<_> = c
        .pub_key_cred_params
        .iter()
        .filter_map(|a| algorithm(*a))
        .collect();
    let rp = relying_party(&c.rp_id, &c.origin, cross);
    let challenge = base::b64url_decode(&c.challenge);
    let mut store: MemStore<Key, Record> = MemStore::default();
    let (Ok(rp), Ok(challenge)) = (rp, challenge) else {
        assert_eq!(c.id, "", "the case sets up");
        return Outcome::NotApplicable;
    };
    let browsers = match (&c.binding, &c.finish_binding) {
        (Some(started), Some(finished)) => browser(started).ok().zip(browser(finished).ok()),
        _ => None,
    };
    assert_eq!(
        browsers.is_some(),
        c.binding.is_some(),
        "{}: the browsers set up",
        c.id
    );
    let parts = Registration {
        challenge: &challenge,
        client_data_json: &c.client_data_json,
        attestation_object: &c.attestation_object,
        requirement,
        algorithms: &algorithms,
        raw_id: c.raw_id.as_deref(),
        browsers: browsers.as_ref().map(|(a, b)| (a, b)),
    };
    let done = register(&mut store, &rp, &parts);
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
        Ok(registered) => {
            let id = registered.credential().id().as_bytes();
            assert_eq!(id, c.expect.credential_id.as_slice(), "{}", c.id);
            let verified = c.expect.user_verified == Some(true);
            assert_eq!(
                registered.user_verification() == webauthn_rp::UserVerification::Verified,
                verified,
                "{}",
                c.id
            );
            let key = CredentialId::from_bytes(id).map(Key::Credential);
            let stored = key
                .ok()
                .and_then(|k| done.left.get(&k).cloned())
                .and_then(|r| r.encode().ok());
            assert_eq!(
                done.left.len(),
                1,
                "{}: one row is left, the credential",
                c.id
            );
            let bytes = stored.unwrap_or_default();
            if let Some(p) = &c.expect.public_key {
                let xy = [p.x.as_slice(), &p.y].concat();
                assert!(
                    bytes.windows(xy.len()).any(|w| w == xy.as_slice()),
                    "{}: the stored key",
                    c.id
                );
            }
        }
        Err(err) => {
            assert_eq!(
                done.left.len(),
                usize::from(!done.finished),
                "{}: a refusal registers nothing",
                c.id
            );
            c.expect.refusal.check(
                &c.id,
                Some(SpecStep::Registration),
                err.kind(),
                err.spec_step(),
            );
        }
    }
    Outcome::Checked
}

/// Every case of `vector` through the ceremony.
pub(crate) fn cases(vector: Vector, floor: usize) {
    let tally = run::<Case>(vector, floor, check);
    assert_eq!(tally.checked(), tally.total());
}
