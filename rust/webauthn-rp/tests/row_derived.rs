//! Row `derived`: the oracle family `vectors/webauthn-rp-derived/`, each file through the reader its ops name; it proves CONTRACT R1 to R9, R16, R17, R33 to R53, R58, R62 to R81, R90, R145.
//! The cbor and cose files reach the readers through `src/`, as row `cbor` does; the rest run through the public constructors and the ceremonies. A case marked `unbuilt` names a reader that lands later, and is skipped until it does.
//! `wycheproof` runs the upstream P-256 ECDSA DER file through `CoseKey::verify`.
#![expect(
    dead_code,
    reason = "the parts of the readers the public constructors reach"
)]
extern crate alloc;
use webauthn_rp::{MAX_CBOR_DEPTH, MAX_CBOR_ITEMS};

#[path = "support/browser.rs"]
mod browser;
#[path = "../src/cbor.rs"]
mod cbor;
#[path = "support/ceremony.rs"]
mod ceremony;
#[path = "../src/cose.rs"]
pub mod cose;
#[path = "../src/error.rs"]
pub mod error;
#[path = "support/hex.rs"]
mod hex;
#[path = "support/assertion.rs"]
mod oracle_assertion;
#[path = "support/attestation_object.rs"]
mod oracle_attestation_object;
#[path = "support/cbor.rs"]
mod oracle_cbor;
#[path = "support/cose.rs"]
mod oracle_cose;
#[path = "support/limits.rs"]
mod oracle_limits;
#[path = "support/origins.rs"]
mod oracle_origins;
#[path = "support/registration.rs"]
mod oracle_registration;
#[path = "support/refusal.rs"]
mod refusal;

#[test]
fn cbor() {
    oracle_cbor::cases();
}

#[test]
fn cose() {
    oracle_cose::cases();
}

#[test]
fn client_data() {
    oracle_assertion::cases(
        testkit::vector!("webauthn-rp-derived/client-data.json"),
        20,
        false,
    );
}

#[test]
fn authenticator_data() {
    oracle_assertion::cases(
        testkit::vector!("webauthn-rp-derived/authenticator-data.json"),
        20,
        false,
    );
}

#[test]
fn registration() {
    oracle_registration::cases(
        testkit::vector!("webauthn-rp-derived/registration.json"),
        17,
    );
}

mod authentication {
    #[test]
    fn steps_5_and_6() {
        super::oracle_assertion::cases(
            testkit::vector!("webauthn-rp-derived/authentication.json"),
            16,
            false,
        );
    }
}

mod registration_ids {
    #[test]
    fn the_raw_id_is_the_attested_id() {
        super::oracle_registration::cases(
            testkit::vector!("webauthn-rp-derived/registration-ids.json"),
            6,
        );
    }
}

// the file holds both ceremonies, so a case is a registration or an assertion by the members it carries
mod browser_binding {
    use serde::Deserialize;
    use testkit::vectors::run;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Case {
        Registration(super::oracle_registration::Case),
        Assertion(super::oracle_assertion::Case),
    }

    #[test]
    fn the_finishing_browser_is_the_starting_one() {
        let tally = run::<Case>(
            testkit::vector!("webauthn-rp-derived/browser-binding.json"),
            8,
            |c| match c {
                Case::Registration(c) => super::oracle_registration::check(c),
                Case::Assertion(c) => super::oracle_assertion::check(c, false),
            },
        );
        assert_eq!(tally.checked(), tally.total());
    }
}

mod origins {
    #[test]
    fn origins_rp_ids_and_app_ids() {
        super::oracle_origins::cases();
    }
}

mod attestation_object {
    #[test]
    fn the_object_has_exactly_three_members() {
        super::oracle_attestation_object::cases();
    }
}

mod limits {
    #[test]
    fn every_bound_holds_and_one_past_is_refused() {
        super::oracle_limits::cases();
    }
}

mod wycheproof {
    use testkit::vectors::{Expected, Outcome, wycheproof};

    use crate::cose::CoseKey;
    use crate::error::ErrorKind;
    use crate::hex::hex_opt;

    fn bytes(text: Option<&str>) -> Vec<u8> {
        let text = text.unwrap_or_default();
        let bytes = hex_opt(serde_json::Value::String(text.to_owned())).unwrap_or_default();
        assert_eq!(bytes.as_ref().map(Vec::len), Some(text.len() / 2), "{text}");
        bytes.unwrap_or_default()
    }

    #[test]
    fn es256_der_signatures() {
        let tally = wycheproof(
            testkit::vector!("wycheproof/ecdsa_secp256r1_sha256_test.json"),
            484,
            |group, case| {
                let point = bytes(
                    group
                        .public_key
                        .as_ref()
                        .and_then(|k| k.uncompressed.as_deref()),
                );
                let (x, y) = (point.get(1..33), point.get(33..65));
                let key = match (x.map(<[u8; 32]>::try_from), y.map(<[u8; 32]>::try_from)) {
                    (Some(Ok(x)), Some(Ok(y))) => CoseKey::Es256 { x, y },
                    _ => return Outcome::NotApplicable,
                };
                let outcome = key
                    .verify(&bytes(case.msg.as_deref()), &bytes(case.sig.as_deref()))
                    .map_err(|e| e.kind());
                let want = match case.result {
                    Expected::Valid => Ok(()),
                    Expected::Invalid => Err(ErrorKind::Signature),
                    _ => return Outcome::NotApplicable,
                };
                assert_eq!(outcome, want, "{}: {}", case.tc_id, case.comment);
                Outcome::Checked
            },
        );
        assert_eq!((tally.total(), tally.checked()), (484, 484));
    }
}
