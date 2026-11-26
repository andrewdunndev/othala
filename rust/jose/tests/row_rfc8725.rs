//! RFC 8725 practices on the compact JWS (CONTRACT R4, R5, R9 to R12, R14).
mod common;

use base::b64url_encode;
use hmac::{Hmac, KeyInit, Mac};
use jose::{Hs256, Jws, SecretJwk};
use proptest::prelude::*;
use proptest::test_runner::{RngSeed, TestError, TestRunner};
use serde::Deserialize;
use sha2::Sha256;
use testkit::vector;
use testkit::vectors::{Json, Outcome, Vector, run};

#[derive(Deserialize)]
struct Expect {
    ok: bool,
    kind: Option<String>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    alg: String,
    jwk: Json,
    jws: String,
    expect: Expect,
}

fn row(file: Vector, total: usize) {
    let tally = run::<Case>(file, total, |case| {
        let outcome = common::verify(&case.alg, case.jwk.text(), &case.jws);
        assert_eq!(outcome.is_ok(), case.expect.ok, "{}", case.id);
        if let Some(named) = &case.expect.kind {
            assert_eq!(
                outcome.err().map(|e| format!("{:?}", e.kind())).as_ref(),
                Some(named),
                "{}",
                case.id
            );
        }
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (total, total));
}

#[test]
fn header_cases() {
    row(vector!("jose-derived/header.json"), 23);
}

#[test]
fn algorithm_confusion() {
    row(vector!("rfc8725-derived/jws-alg.json"), 25);
}

const KEY: &str =
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

/// A valid HS256 token whose header carries `kid` and the members a verifier must never act on.
fn token(kid: &str, extra: &str) -> String {
    let key = base::b64url_decode(KEY).unwrap_or_default();
    let header = format!(
        r#"{{"alg":"HS256","kid":{},{extra}"x":0}}"#,
        serde_json::to_string(kid).unwrap_or_default()
    );
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(b"payload")
    );
    Hmac::<Sha256>::new_from_slice(&key)
        .map(|mut mac| {
            mac.update(input.as_bytes());
            format!("{input}.{}", b64url_encode(&mac.finalize().into_bytes()))
        })
        .unwrap_or_default()
}

#[test]
fn kid_never_selects() -> Result<(), TestError<(String, usize)>> {
    let extras = [
        "",
        r#""jku":"https://attacker.example/keys","#,
        r#""jwk":{"kty":"oct","k":"AA"},"#,
        r#""x5u":"https://attacker.example/c","x5c":["AA"],"#,
    ];
    let config = ProptestConfig {
        cases: 128,
        rng_seed: RngSeed::Fixed(0x5eed_0002),
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    let key = SecretJwk::decode(format!(r#"{{"kty":"oct","k":"{KEY}"}}"#).as_bytes())
        .and_then(|k| k.verify_key::<Hs256>());
    TestRunner::new(config).run(&(".{0,40}", 0..extras.len()), |(kid, extra)| {
        let text = token(&kid, extras.get(extra).copied().unwrap_or_default());
        let parsed = Jws::parse(&text);
        prop_assert!(parsed.is_ok());
        let payload = parsed.and_then(|jws| jws.verify(key.as_ref().map_err(|e| *e)?));
        prop_assert_eq!(
            payload.map(|p| p.bytes().to_vec()).ok(),
            Some(b"payload".to_vec())
        );
        Ok(())
    })
}
