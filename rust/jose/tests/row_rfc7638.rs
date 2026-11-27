//! RFC 7638 thumbprints (CONTRACT R25) and the `kid` made from one.
use std::collections::BTreeMap;

use jose::{Jwk, Kid, SecretJwk};
use serde::Deserialize;
use testkit::vector;
use testkit::vectors::{Json, Outcome, Vector, run};

#[derive(Deserialize)]
struct Expect {
    out: Option<String>,
    ok: Option<bool>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    jwk: Json,
    expect: Expect,
}

fn row(file: Vector, floor: usize, total: usize) {
    let tally = run::<Case>(file, floor, |case| {
        let members = case.jwk.parse::<BTreeMap<String, Json>>();
        let secret =
            members.contains_key("d") || members.get("kty").is_some_and(|k| k.text() == "\"oct\"");
        let json = case.jwk.text().as_bytes();
        let digest = if secret {
            SecretJwk::decode(json).map(|key| key.thumbprint())
        } else {
            Jwk::decode(json).map(|key| key.thumbprint())
        };
        match (&case.expect.out, case.expect.ok) {
            (Some(out), _) => {
                let digest = digest.ok();
                assert_eq!(
                    digest.map(|d| d.to_b64url()).as_ref(),
                    Some(out),
                    "{}",
                    case.id
                );
                assert_eq!(
                    digest
                        .map(|d| Kid::from_thumbprint(&d).as_str().to_owned())
                        .as_ref(),
                    Some(out)
                );
            }
            (None, ok) => assert_eq!(
                (ok, digest.err().map(|e| e.kind())),
                (
                    Some(false),
                    Some(if case.id == "kty-unknown" {
                        jose::ErrorKind::UnsupportedAlg
                    } else {
                        jose::ErrorKind::Malformed
                    })
                ),
                "{}",
                case.id
            ),
        }
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (total, total));
}

#[test]
fn rfc7638_section_3() {
    row(vector!("rfc7638/thumbprint.json"), 3, 3);
}

#[test]
fn derived_thumbprints() {
    row(vector!("jose-derived/thumbprint.json"), 7, 7);
}
