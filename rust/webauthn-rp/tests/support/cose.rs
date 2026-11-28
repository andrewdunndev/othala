//! The oracle's `cose.json` through the strict reader and `CoseKey::parse`; the algorithms beyond ES256 are unbuilt.
use serde::Deserialize;
use testkit::vectors::{Outcome, run};

use crate::cbor::{Order, decode};
use crate::cose::{CoseAlgorithm, CoseKey};
use crate::error::ErrorKind;
use crate::hex::hex;
use crate::refusal::Refusal;

#[derive(Deserialize)]
struct Expect {
    ok: bool,
    alg: Option<i64>,
    #[serde(flatten)]
    refusal: Refusal,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    #[serde(deserialize_with = "hex")]
    input: Vec<u8>,
    unbuilt: Option<String>,
    expect: Expect,
}

pub(crate) fn cases() {
    let tally = run::<Case>(testkit::vector!("webauthn-rp-derived/cose.json"), 22, |c| {
        let key = decode(&c.input, Order::Canonical).and_then(|value| CoseKey::parse(&value));
        if c.unbuilt.is_some() {
            // a case that must be accepted proves its marker true: the reader refuses it today, and for the reason its code gives:
            // a kty and alg other than ES256 are `Algorithm`, except RS256, whose `n` sits at label -1 and is read as a non-integer `crv`, `Malformed`
            if c.expect.ok {
                let kind = if c.expect.alg == Some(-257) {
                    ErrorKind::Malformed
                } else {
                    ErrorKind::Algorithm
                };
                assert_eq!(
                    key.as_ref().err().map(|e| e.kind()),
                    Some(kind),
                    "{}: built or refused otherwise, drop or revise the marker",
                    c.id
                );
            }
            return Outcome::NotApplicable;
        }
        match key {
            Ok(key) => {
                assert!(c.expect.ok, "{}: accepted", c.id);
                assert_eq!(
                    (key.algorithm(), c.expect.alg),
                    (CoseAlgorithm::Es256, Some(-7)),
                    "{}",
                    c.id
                );
            }
            Err(err) => {
                assert!(!c.expect.ok, "{}: refused as {:?}", c.id, err.kind());
                c.expect
                    .refusal
                    .check(&c.id, None, err.kind(), err.spec_step());
            }
        }
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (50, 22));
}
