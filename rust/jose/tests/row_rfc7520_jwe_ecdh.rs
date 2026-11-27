//! RFC 7520 5.4, 5.5 and 5.13 (recipient 2): the ECDH-ES JWEs in each serialization given (CONTRACT R49, R52, R57).
mod common_jwe;

use base::{Entropy, b64url_decode, b64url_encode};
use jose::{
    A128CbcHs256, A128Gcm, A256CbcHs512, Dir, EcdhEs, EcdhEsA128Kw, EcdhEsA192Kw, EcdhEsA256Kw,
    Enc, ErrorKind, Jwe, Jwk, LocalKeyAlg, PublicKeyAlg, SecretJwk,
};
use proptest::prelude::*;
use proptest::test_runner::{RngSeed, TestRunner};
use serde::Deserialize;
use testkit::vector;
use testkit::vectors::{Json, Outcome, run};

#[derive(Deserialize)]
struct Expect {
    ok: bool,
    plaintext: Option<String>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    alg: String,
    enc: String,
    serialization: String,
    jwk: Option<Json>,
    jwe: Json,
    expect: Expect,
}

fn parse(compact: bool, wire: &str) -> Result<Jwe<'_>, jose::Error> {
    if compact {
        Jwe::parse(wire)
    } else {
        Jwe::parse_json(wire.as_bytes())
    }
}

#[test]
fn ecdh_es() {
    let tally = run::<Case>(vector!("rfc7520/jwe-cases.json"), 1, |case| {
        if common_jwe::LOCAL.contains(&case.alg.as_str()) || !case.alg.starts_with("ECDH-ES") {
            return Outcome::NotApplicable;
        }
        let jwk = case.jwk.as_ref().map_or("{}", Json::text);
        let compact = case.serialization == "compact";
        let wire = if compact {
            case.jwe.parse::<String>()
        } else {
            case.jwe.text().to_owned()
        };
        let outcome = parse(compact, &wire)
            .and_then(|jwe| common_jwe::decrypt(&case.alg, &case.enc, jwk, jwe));
        // a token the parser refuses is Malformed; one the decryption refuses is Decrypt
        assert_eq!(
            outcome
                .as_ref()
                .err()
                .map(|e| matches!(e.kind(), ErrorKind::Decrypt | ErrorKind::Malformed)),
            (!case.expect.ok).then_some(true),
            "{}",
            case.id
        );
        if let Some(want) = &case.expect.plaintext {
            let got = outcome.ok().map(|plaintext| b64url_encode(&plaintext));
            assert_eq!(got.as_ref(), Some(want), "{}", case.id);
        }
        Outcome::Checked
    });
    assert_eq!(tally.total(), 64);
    assert_eq!(tally.checked(), 16);
}

/// A counter standing in for entropy: one seed is one token.
struct Counter(u8);

impl Entropy for Counter {
    fn fill(&mut self, out: &mut [u8]) {
        for byte in out {
            self.0 = self.0.wrapping_mul(37).wrapping_add(11);
            *byte = self.0;
        }
    }
}

#[derive(Deserialize)]
struct Keys {
    id: String,
    private_jwk: Json,
    public_jwk: Json,
}

/// `decrypt(encrypt(x)) = x` to the recipient of RFC 7518 Appendix C, one seed gives one token, and a changed byte of
/// any later segment is `Decrypt`.
fn round<K: LocalKeyAlg + PublicKeyAlg, E: Enc>(
    recipient: &(Jwk, SecretJwk),
    plaintext: &[u8],
    seed: u8,
    at: usize,
) -> Result<(), TestCaseError> {
    let encrypt = recipient
        .0
        .encrypt_key::<K>()
        .map_err(|_| TestCaseError::fail("encrypt key"))?;
    let decrypt = recipient
        .1
        .decrypt_key::<K>()
        .map_err(|_| TestCaseError::fail("decrypt key"))?;
    let token = encrypt
        .encrypt::<E>(plaintext, &mut Counter(seed))
        .map_err(|_| TestCaseError::fail("encrypt"))?;
    let again = encrypt
        .encrypt::<E>(plaintext, &mut Counter(seed))
        .map_err(|_| TestCaseError::fail("encrypt"))?;
    prop_assert_eq!(token.as_str(), again.as_str());
    let opened = Jwe::parse(token.as_str())
        .and_then(|jwe| jwe.decrypt::<K, E>(&decrypt))
        .map_err(|_| TestCaseError::fail("decrypt"))?;
    prop_assert_eq!(opened.bytes(), plaintext);
    let mut parts: Vec<String> = token.as_str().split('.').map(str::to_owned).collect();
    let index = 2 + at % 3;
    let mut segment = parts
        .get(index)
        .and_then(|p| b64url_decode(p).ok())
        .unwrap_or_default();
    let place = at % segment.len().max(1);
    if let Some(byte) = segment.get_mut(place) {
        *byte ^= 1;
        if let Some(part) = parts.get_mut(index) {
            *part = b64url_encode(&segment);
        }
        let failed = Jwe::parse(&parts.join(".")).and_then(|jwe| jwe.decrypt::<K, E>(&decrypt));
        prop_assert_eq!(failed.err().map(|e| e.kind()), Some(ErrorKind::Decrypt));
    }
    Ok(())
}

#[test]
fn ecdh_round_trip() {
    let mut recipient = None;
    let tally = run::<Keys>(vector!("rfc7518/appendix-c.json"), 1, |keys| {
        if keys.id == "c-recipient" {
            let public = Jwk::decode(keys.public_jwk.text().as_bytes());
            let private = SecretJwk::decode(keys.private_jwk.text().as_bytes());
            let own = private.as_ref().ok().and_then(SecretJwk::public);
            recipient = own.zip(private.ok());
            let _ = public;
        }
        Outcome::Checked
    });
    assert_eq!(tally.checked(), tally.total());
    assert!(recipient.is_some());
    let config = ProptestConfig {
        cases: 24,
        rng_seed: RngSeed::Fixed(0x5eed_0007),
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    let strategy = (
        proptest::collection::vec(any::<u8>(), 0..80),
        any::<u8>(),
        any::<usize>(),
    );
    let outcome = TestRunner::new(config).run(&strategy, |(payload, seed, at)| {
        if let Some(recipient) = &recipient {
            round::<EcdhEs, A128Gcm>(recipient, &payload, seed, at)?;
            round::<EcdhEs, A256CbcHs512>(recipient, &payload, seed, at)?;
            round::<EcdhEsA128Kw, A128CbcHs256>(recipient, &payload, seed, at)?;
            round::<EcdhEsA192Kw, A128Gcm>(recipient, &payload, seed, at)?;
            round::<EcdhEsA256Kw, A256CbcHs512>(recipient, &payload, seed, at)?;
        }
        Ok(())
    });
    assert_eq!(outcome, Ok(()));
    let _ = Dir;
}
