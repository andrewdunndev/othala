//! RFC 7520 section 6, a PS256 JWT nested in an RSA-OAEP and A128GCM JWE with `cty` `JWT` (CONTRACT R38, R60): each
//! serialization decrypts to the inner token, which verifies and is read on its own. With the features off the outer
//! JWE is `UnsupportedAlg`, checked in `row_features_off`.
#![cfg(all(feature = "rsa-decrypt", feature = "rsa-sign"))]
mod common_figures;

use base::{Entropy, UnixTime, b64url_decode, b64url_encode};
use jose::{
    A128Gcm, Audience, ErrorKind, Issuer, Jwe, Jws, Jwt, Leeway, Policy, Ps256, RsaOaep, SecretJwk,
    TokenKind, Typ,
};
use serde::Deserialize;
use testkit::vector;
use testkit::vectors::Figures;

#[derive(Deserialize)]
struct Claims {}

struct Nested;

impl TokenKind for Nested {
    const TYP: Typ = Typ::Generic;
    type Claims = Claims;
}

struct Counter(testkit::Seeded);

impl Entropy for Counter {
    fn fill(&mut self, out: &mut [u8]) {
        self.0.fill(out);
    }
}

/// A figure's `joined` text, counted: a figure the file lacks is empty text, which a refusal would accept.
fn figure(file: &Figures, number: u32, visited: &std::cell::Cell<usize>) -> String {
    let all = file
        .shared
        .iter()
        .chain(file.examples.iter().flat_map(|e| e.figures.iter()));
    let text = all
        .filter(|f| f.figure == number)
        .map(|f| f.joined.clone())
        .next()
        .unwrap_or_default();
    assert!(!text.is_empty(), "figure {number} is not in the file");
    visited.set(visited.get() + 1);
    text
}

fn decrypt(outer: &SecretJwk, wire: &str, json: bool) -> Result<Vec<u8>, jose::Error> {
    let key = outer.decrypt_key::<RsaOaep>()?;
    let jwe = if json {
        Jwe::parse_json(wire.as_bytes())?
    } else {
        Jwe::parse(wire)?
    };
    let mut entropy = Counter(testkit::seeded(6));
    jwe.decrypt_blinded::<RsaOaep, A128Gcm>(&key, &mut entropy)
        .map(|p| p.bytes().to_vec())
}

#[test]
fn nested_jwt() {
    let (outer_file, inner_file) = (
        common_figures::all(vector!("rfc7520/jwe.json")),
        common_figures::all(vector!("rfc7520/nesting.json")),
    );
    let visited = std::cell::Cell::new(0);
    let outer = SecretJwk::decode(figure(&outer_file, 84, &visited).as_bytes()).ok();
    let signer = SecretJwk::decode(figure(&inner_file, 224, &visited).as_bytes()).ok();
    let (outer, verify) = (
        outer.as_ref(),
        signer.and_then(|k| k.verify_key::<Ps256>().ok()),
    );
    let verify = verify.as_ref();
    assert!(outer.is_some(), "outer key");
    assert!(verify.is_some(), "inner key");
    let inner = figure(&inner_file, 228, &visited);
    let payload = figure(&inner_file, 222, &visited);

    // R60: the outer JWE says `cty` `JWT` and opens, in all three serializations, to the inner compact JWS
    let header = figure(&inner_file, 232, &visited);
    assert_eq!(
        b64url_decode(&figure(&inner_file, 233, &visited)).ok(),
        Some(header.clone().into_bytes())
    );
    assert_eq!(header, r#"{"alg":"RSA-OAEP","cty":"JWT","enc":"A128GCM"}"#);
    for (number, json) in [(236, false), (237, true), (238, true)] {
        let wire = figure(&inner_file, number, &visited);
        let opened = outer.map(|k| decrypt(k, &wire, json));
        assert_eq!(
            opened.and_then(|r| r.ok()),
            Some(inner.clone().into_bytes()),
            "figure {number}"
        );
    }

    // R38: the inner token verifies on its own and its payload is Figure 222; its own header has no `cty`, so
    // `claims` goes past the `cty` step and stops at the absent `aud`
    let signed = Jws::parse(&inner)
        .and_then(|jws| jws.verify(verify.ok_or(ErrorKind::KeyUse)?))
        .map(|p| p.bytes().to_vec());
    assert_eq!(signed.ok(), Some(payload.clone().into_bytes()));
    assert_eq!(
        b64url_decode(&figure(&inner_file, 223, &visited)).ok(),
        Some(payload.into_bytes())
    );
    let policy = Issuer::new("hobbiton.example")
        .and_then(|iss| Policy::<Nested>::new(iss, Audience::new("any")?, Leeway::new(0)?));
    let claims = Jwt::parse(&inner)
        .and_then(|jwt| jwt.verify(verify.ok_or(ErrorKind::KeyUse)?))
        .and_then(|jwt| jwt.claims(&policy?, UnixTime::new(1_300_819_000)));
    assert_eq!(
        claims.err().map(|e| e.kind()),
        Some(ErrorKind::MissingClaim)
    );

    // a changed byte of the signature is refused as `BadSignature`
    let mut parts: Vec<String> = inner.split('.').map(str::to_owned).collect();
    let mut signature = parts.last().and_then(|p| b64url_decode(p).ok());
    if let Some(byte) = signature.as_mut().and_then(|s| s.first_mut()) {
        *byte ^= 1;
    }
    if let (Some(last), Some(signature)) = (parts.last_mut(), signature) {
        *last = b64url_encode(&signature);
    }
    let tampered =
        Jws::parse(&parts.join(".")).and_then(|jws| jws.verify(verify.ok_or(ErrorKind::KeyUse)?));
    assert_eq!(
        tampered.err().map(|e| e.kind()),
        Some(ErrorKind::BadSignature)
    );
    // 84, 224, 228, 222, 232, 233, 236 to 238, 223
    assert_eq!(visited.get(), 10);
}
