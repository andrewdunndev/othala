//! Every bound refuses with `TooLarge` (CONTRACT R61): vec:jose-derived/limits.json.
use base::{UnixTime, b64url_encode};
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
struct Case {
    id: String,
    jwk: Json,
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

fn nested(depth: usize) -> String {
    format!("{}{}", "[".repeat(depth), "]".repeat(depth))
}

fn claims(jwk: &str, jwt: &str) -> Result<(), jose::Error> {
    let policy = Policy::<Plain>::new(Issuer::new("i")?, Audience::new("a")?, Leeway::new(0)?)?;
    let key = SecretJwk::decode(jwk.as_bytes())?.verify_key::<Hs256>()?;
    Jwt::parse(jwt)?
        .verify(&key)?
        .claims(&policy, UnixTime::new(0))
        .map(|_| ())
}

#[test]
fn bounds() {
    let tally = run::<Case>(vector!("jose-derived/limits.json"), 4, |case| {
        let jwk = case.jwk.text();
        let secret = SecretJwk::decode(jwk.as_bytes()).ok();
        let members = case
            .jwk
            .parse::<std::collections::BTreeMap<String, String>>();
        let k =
            base::b64url_decode(members.get("k").map_or("", String::as_str)).unwrap_or_default();
        let outcome = match case.id.as_str() {
            "compact-bytes" => {
                let longer = (12_000..)
                    .map(|n| token(&k, r#"{"alg":"HS256"}"#, &"a".repeat(n)))
                    .find(|t| t.len() > MAX_COMPACT_LEN);
                let longer = longer.unwrap_or_default();
                assert_eq!(longer.len(), MAX_COMPACT_LEN + 1);
                claims(jwk, &longer)
            }
            "header-depth" => {
                let header = format!(r#"{{"alg":"HS256","x":{}}}"#, nested(MAX_JSON_DEPTH));
                claims(jwk, &token(&k, &header, "{}"))
            }
            "claims-depth" => {
                let payload = format!(r#"{{"x":{}}}"#, nested(MAX_JSON_DEPTH));
                claims(jwk, &token(&k, r#"{"alg":"HS256"}"#, &payload))
            }
            _ => {
                let keys: Vec<String> = (0..=MAX_JWKS_KEYS)
                    .map(|i| jwk.replacen('{', &format!(r#"{{"kid":"k{i}","#), 1))
                    .collect();
                JwkSet::decode(format!(r#"{{"keys":[{}]}}"#, keys.join(",")).as_bytes()).map(|_| ())
            }
        };
        assert!(secret.is_some() && Jwk::decode(jwk.as_bytes()).is_err());
        assert_eq!(
            outcome.err().map(|e| e.kind()),
            Some(ErrorKind::TooLarge),
            "{}",
            case.id
        );
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (4, 4));
}
