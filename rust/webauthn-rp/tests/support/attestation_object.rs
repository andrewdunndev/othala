//! The oracle's `attestation-object.json` through `RegistrationResponse::new`, which reads the object before any finish runs.
use serde::Deserialize;
use testkit::vectors::{Outcome, run};
use webauthn_rp::{RegistrationResponse, SpecStep};

use crate::ceremony::attested_id;
use crate::hex::hex;
use crate::refusal::Refusal;

#[derive(Deserialize)]
struct Expect {
    ok: bool,
    #[serde(flatten)]
    refusal: Refusal,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    #[serde(deserialize_with = "hex")]
    input: Vec<u8>,
    expect: Expect,
}

// a well-formed create response's clientDataJSON, so that only the attestation object can be refused
const CLIENT_DATA: &[u8] = br#"{"type":"webauthn.create","challenge":"EijdmqrPNtPCSCR4aUB_y-czWE3Q7fYuiakE10n5Mdc","origin":"https://example.org","crossOrigin":false}"#;

pub(crate) fn cases() {
    let tally = run::<Case>(
        testkit::vector!("webauthn-rp-derived/attestation-object.json"),
        22,
        |c| {
            match RegistrationResponse::new(&attested_id(&c.input), CLIENT_DATA, &c.input, &[]) {
                Ok(_) => assert!(c.expect.ok, "{}: accepted", c.id),
                Err(err) => {
                    assert!(!c.expect.ok, "{}: refused as {:?}", c.id, err.kind());
                    c.expect.refusal.check(
                        &c.id,
                        Some(SpecStep::Registration),
                        err.kind(),
                        err.spec_step(),
                    );
                }
            }
            Outcome::Checked
        },
    );
    assert_eq!(tally.checked(), tally.total());
}
