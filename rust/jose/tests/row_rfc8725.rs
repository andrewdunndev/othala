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
        testkit::vectors::assert_verdict(
            &outcome,
            case.expect.ok,
            case.expect.kind.as_deref(),
            |e| e.kind(),
            &case.id,
        );
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (total, total));
}

//= https://www.rfc-editor.org/rfc/rfc7515#section-4
//= type=test
//# The Header Parameter names within the JOSE Header MUST be unique; JWS parsers MUST either reject
//# JWSs with duplicate Header Parameter names or use a JSON parser that returns only the lexically
//# last duplicate member name, as specified in Section 15.12 ("The JSON Object") of ECMAScript 5.1
//# [ECMAScript].
//= https://www.rfc-editor.org/rfc/rfc7515#section-10.12
//= type=test
//# The Header Parameter names within the JOSE Header MUST be unique; JWS parsers MUST either reject
//# JWSs with duplicate Header Parameter names or use a JSON parser that returns only the lexically
//# last duplicate member name, as specified in Section 15.12 ("The JSON Object") of ECMAScript 5.1
//# [ECMAScript].
//= https://www.rfc-editor.org/rfc/rfc7515#section-10.12
//= type=test
//# Thus, this specification requires that the "SHOULD" in Section 4 of [RFC7159] be treated as a
//# "MUST" by producers and that it be either treated as a "MUST" or treated in the manner specified
//# in ECMAScript 5.1 by consumers.
//= https://www.rfc-editor.org/rfc/rfc7515#section-10.12
//= type=test
//# In particular, any JSON inputs not conforming to the JSON-text syntax defined in RFC 7159 MUST
//# be rejected in their entirety by JSON parsers.
//= https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1
//= type=test
//# This Header Parameter MUST be present and MUST be understood and processed by implementations.
//= https://www.rfc-editor.org/rfc/rfc7515#section-4
//= type=test
//# Implementations are required to understand the specific Header Parameters defined by this
//# specification that are designated as "MUST be understood" and process them in the manner defined
//# in this specification.
//= https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11
//= type=test
//# The "crit" (critical) Header Parameter indicates that extensions to this specification and/or
//# [JWA] are being used that MUST be understood and processed.
//= https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11
//= type=test
//# This Header Parameter MUST be understood and processed by implementations.
//= https://www.rfc-editor.org/rfc/rfc7515#section-5.3
//= type=test
//# These comparison rules MUST be used for all JSON string comparisons except in cases where the
//# definition of the member explicitly calls out that a different comparison rule is to be used for
//# that member value.
#[test]
fn header_cases() {
    row(vector!("jose-derived/header.json"), 25);
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

//= https://www.rfc-editor.org/rfc/rfc7515#section-4
//= type=test
//# All other Header Parameters defined by this specification that are not so designated MUST be
//# ignored when not understood.
//= https://www.rfc-editor.org/rfc/rfc7515#section-4
//= type=test
//# Unless listed as a critical Header Parameter, per Section 4.1.11, all Header Parameters not
//# defined by this specification MUST be ignored when not understood.
//= https://www.rfc-editor.org/rfc/rfc7515#section-6
//= type=test
//# These Header Parameters MUST be integrity protected if the information that they convey is to be
//# utilized in a trust decision; however, if the only information used in the trust decision is a
//# key, these parameters need not be integrity protected, since changing them in a way that causes
//# a different key to be used will cause the validation to fail.
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
        prop_assert_eq!(parsed.as_ref().err().map(|e| e.kind()), None);
        let payload = parsed.and_then(|jws| jws.verify(key.as_ref().map_err(|e| *e)?));
        prop_assert_eq!(
            payload.map(|p| p.bytes().to_vec()).ok(),
            Some(b"payload".to_vec())
        );
        Ok(())
    })
}
