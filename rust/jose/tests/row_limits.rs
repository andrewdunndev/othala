//! Every bound refuses with `TooLarge` (CONTRACT R61): vec:jose-derived/limits.json.
use base::{UnixTime, b64url_decode, b64url_encode};
use hmac::{Hmac, KeyInit, Mac};
use jose::{
    Audience, ErrorKind, Hs256, Issuer, Jwk, JwkSet, Jwt, Leeway, Policy, SecretJwk, TokenKind, Typ,
};
use jose::{MAX_COMPACT_LEN, MAX_JSON_DEPTH, MAX_JWKS_KEYS};
use serde::Deserialize;
use sha2::Sha256;
use testkit::vector;
use testkit::vectors::{Json, Outcome, run};

#[derive(Deserialize)]
struct Claims {}

struct Plain;

impl TokenKind for Plain {
    const TYP: Typ = Typ::Generic;
    type Claims = Claims;
}

#[derive(Deserialize)]
struct Repeat {
    byte: String,
    count: usize,
}

#[derive(Deserialize)]
struct Expect {
    ok: Option<bool>,
    kind: Option<String>,
    not_kind: Option<String>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    jwk: Json,
    header_json: Option<String>,
    payload_json: Option<String>,
    payload_repeat: Option<Repeat>,
    input: Option<String>,
    token_len: Option<usize>,
    expect: Expect,
}

/// A token over `header` and `payload` with a valid HS256 signature under `key`.
fn token(key: &[u8], header: &str, payload: &str) -> String {
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(payload.as_bytes())
    );
    Hmac::<Sha256>::new_from_slice(key)
        .map(|mut mac| {
            mac.update(input.as_bytes());
            format!("{input}.{}", b64url_encode(&mac.finalize().into_bytes()))
        })
        .unwrap_or_default()
}

/// Verifies `jwt` under `jwk`; with `through_claims` also reads its claims under a policy.
fn read(jwk: &str, jwt: &str, through_claims: bool) -> Result<(), jose::Error> {
    let policy = Policy::<Plain>::new(Issuer::new("i")?, Audience::new("a")?, Leeway::new(0)?)?;
    let key = SecretJwk::decode(jwk.as_bytes())?.verify_key::<Hs256>()?;
    let verified = Jwt::parse(jwt)?.verify(&key)?;
    if through_claims {
        verified.claims(&policy, UnixTime::new(0)).map(|_| ())
    } else {
        Ok(())
    }
}

fn nested(depth: usize) -> String {
    format!("{}{}", "[".repeat(depth), "]".repeat(depth))
}

/// The inputs of a case whose row carries none (the file before the oracle gave them): main's four ids only.
fn rebuilt(case: &Case, jwk: &str, k: &[u8]) -> (Option<String>, Option<String>) {
    match case.id.as_str() {
        "compact-bytes" => {
            let longer = (12_000..)
                .map(|n| token(k, r#"{"alg":"HS256"}"#, &"a".repeat(n)))
                .find(|t| t.len() > MAX_COMPACT_LEN);
            assert_eq!(longer.as_ref().map(String::len), Some(MAX_COMPACT_LEN + 1));
            (longer, None)
        }
        "header-depth" => {
            let header = format!(r#"{{"alg":"HS256","x":{}}}"#, nested(MAX_JSON_DEPTH));
            (Some(token(k, &header, "{}")), None)
        }
        "claims-depth" => {
            let payload = format!(r#"{{"x":{}}}"#, nested(MAX_JSON_DEPTH));
            (Some(token(k, r#"{"alg":"HS256"}"#, &payload)), None)
        }
        "jwks-key-count" => {
            let keys: Vec<String> = (0..=MAX_JWKS_KEYS)
                .map(|i| jwk.replacen('{', &format!(r#"{{"kid":"k{i}","#), 1))
                .collect();
            (None, Some(format!(r#"{{"keys":[{}]}}"#, keys.join(","))))
        }
        _ => (None, None),
    }
}

fn kind_name(kind: ErrorKind) -> String {
    format!("{kind:?}")
}

#[test]
fn bounds() {
    let tally = run::<Case>(vector!("jose-derived/limits.json"), 4, |case| {
        let jwk = case.jwk.text();
        assert!(
            SecretJwk::decode(jwk.as_bytes()).is_ok() && Jwk::decode(jwk.as_bytes()).is_err(),
            "{}",
            case.id
        );
        let members = case
            .jwk
            .parse::<std::collections::BTreeMap<String, String>>();
        let k = b64url_decode(members.get("k").map_or("", String::as_str)).unwrap_or_default();
        let (jwt, set) = match (&case.header_json, &case.input) {
            (Some(header), None) => {
                let payload = case
                    .payload_json
                    .clone()
                    .or_else(|| case.payload_repeat.as_ref().map(|r| r.byte.repeat(r.count)));
                assert!(payload.is_some(), "{}: no payload", case.id);
                let jwt = token(&k, header, &payload.unwrap_or_default());
                if let Some(len) = case.token_len {
                    assert_eq!(jwt.len(), len, "{}", case.id);
                }
                (Some(jwt), None)
            }
            (None, Some(input)) => (None, Some(input.clone())),
            (None, None) if case.payload_json.is_none() && case.payload_repeat.is_none() => {
                rebuilt(case, jwk, &k)
            }
            _ => (None, None),
        };
        assert!(jwt.is_some() != set.is_some(), "{}: no inputs", case.id);
        let outcome = match (&jwt, &set) {
            (Some(jwt), _) => read(jwk, jwt, case.expect.ok != Some(true)),
            (None, Some(set)) => JwkSet::decode(set.as_bytes()).map(|_| ()),
            (None, None) => Ok(()),
        };
        let got = outcome.err().map(|e| kind_name(e.kind()));
        let held = match (&case.expect.ok, &case.expect.kind, &case.expect.not_kind) {
            (Some(true), None, None) => got.is_none(),
            (Some(false), Some(kind), None) => got.as_ref() == Some(kind),
            (None, None, Some(not)) => got.as_ref() != Some(not),
            _ => false,
        };
        assert!(
            held,
            "{}: got {got:?} against {:?}",
            case.id,
            (&case.expect.ok, &case.expect.kind, &case.expect.not_kind)
        );
        Outcome::Checked
    });
    assert_eq!(tally.checked(), tally.total());
}
