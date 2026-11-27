//! RSA-OAEP and RSA-OAEP-256 (CONTRACT R48, R49, R54, R59): RFC 7516 A.1, RFC 7520 5.2, a round trip and the one
//! decryption path.
#![cfg(feature = "rsa-decrypt")]

use base::{Entropy, b64url_decode, b64url_encode};
use jose::{
    A128CbcHs256, A128Gcm, A256CbcHs512, A256Gcm, BlindedKeyAlg, Enc, ErrorKind, Jwe, Jwk,
    PublicKeyAlg, RsaOaep, RsaOaep256, SecretJwk,
};
use proptest::prelude::*;
use proptest::test_runner::{RngSeed, TestRunner};
use serde::Deserialize;
use testkit::vector;
use testkit::vectors::{Json, Outcome, Vector, run};

/// Seeded entropy that counts its draws.
struct Counter(testkit::Seeded, usize);

impl Counter {
    fn new(seed: u8, _: usize) -> Self {
        Self(testkit::seeded(u64::from(seed)), 0)
    }
}

impl Entropy for Counter {
    fn fill(&mut self, out: &mut [u8]) {
        self.1 += 1;
        self.0.fill(out);
    }
}

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
    jwk: Option<Json>,
    jwe: Json,
    serialization: Option<String>,
    expect: Expect,
}

fn under<K: BlindedKeyAlg, E: Enc>(
    jwk: &str,
    jwe: Jwe<'_>,
    draws: &mut Counter,
) -> Result<Vec<u8>, jose::Error> {
    let key = SecretJwk::decode(jwk.as_bytes())?.decrypt_key::<K>()?;
    jwe.decrypt_blinded::<K, E>(&key, draws)
        .map(|p| p.bytes().to_vec())
}

fn by_enc<K: BlindedKeyAlg>(
    enc: &str,
    jwk: &str,
    jwe: Jwe<'_>,
    draws: &mut Counter,
) -> Result<Vec<u8>, jose::Error> {
    match enc {
        "A256GCM" => under::<K, A256Gcm>(jwk, jwe, draws),
        "A128GCM" => under::<K, A128Gcm>(jwk, jwe, draws),
        "A128CBC-HS256" => under::<K, A128CbcHs256>(jwk, jwe, draws),
        _ => Err(ErrorKind::UnsupportedAlg.into()),
    }
}

fn parse(compact: bool, wire: &str) -> Result<Jwe<'_>, jose::Error> {
    if compact {
        Jwe::parse(wire)
    } else {
        Jwe::parse_json(wire.as_bytes())
    }
}

fn row(file: Vector, total: usize, checked: usize) {
    let tally = run::<Case>(file, 1, |case| {
        if !case.alg.starts_with("RSA-OAEP") {
            return Outcome::NotApplicable;
        }
        let compact = case.serialization.as_deref().is_none_or(|s| s == "compact");
        let wire = if compact {
            case.jwe.parse::<String>()
        } else {
            case.jwe.text().to_owned()
        };
        let mut draws = Counter::new(1, 0);
        let outcome = parse(compact, &wire).and_then(|jwe| match case.alg.as_str() {
            "RSA-OAEP" => by_enc::<RsaOaep>(
                &case.enc,
                case.jwk.as_ref().map_or("{}", Json::text),
                jwe,
                &mut draws,
            ),
            _ => by_enc::<RsaOaep256>(
                &case.enc,
                case.jwk.as_ref().map_or("{}", Json::text),
                jwe,
                &mut draws,
            ),
        });
        // a token that does not parse is refused whole; one that parses is refused by the decryption
        let refusal = if parse(compact, &wire).map(drop) == Ok(()) {
            ErrorKind::Decrypt
        } else {
            ErrorKind::Malformed
        };
        assert_eq!(
            outcome.as_ref().err().map(|e| e.kind()),
            (!case.expect.ok).then_some(refusal),
            "{}",
            case.id
        );
        if let Some(want) = &case.expect.plaintext {
            assert_eq!(
                outcome.ok().map(|p| b64url_encode(&p)).as_ref(),
                Some(want),
                "{}",
                case.id
            );
        }
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (total, checked));
}

#[test]
fn rfc7516_a1_and_rfc7520_5_2() {
    row(vector!("rfc7516/jwe.json"), 13, 6);
    row(vector!("rfc7520/jwe-cases.json"), 64, 8);
}

fn round<K: BlindedKeyAlg + PublicKeyAlg, E: Enc>(
    keys: &(Jwk, SecretJwk),
    plaintext: &[u8],
    seed: u8,
    at: usize,
) -> Result<(), TestCaseError> {
    let encrypt = keys
        .0
        .encrypt_key::<K>()
        .map_err(|_| TestCaseError::fail("encrypt key"))?;
    let decrypt = keys
        .1
        .decrypt_key::<K>()
        .map_err(|_| TestCaseError::fail("decrypt key"))?;
    let token = encrypt
        .encrypt::<E>(plaintext, &mut Counter::new(seed, 0))
        .map_err(|_| TestCaseError::fail("encrypt"))?;
    let again = encrypt
        .encrypt::<E>(plaintext, &mut Counter::new(seed, 0))
        .map_err(|_| TestCaseError::fail("encrypt"))?;
    prop_assert_eq!(token.as_str(), again.as_str());
    let opened = Jwe::parse(token.as_str())
        .and_then(|jwe| jwe.decrypt_blinded::<K, E>(&decrypt, &mut Counter::new(seed, 0)))
        .map_err(|_| TestCaseError::fail("decrypt"))?;
    prop_assert_eq!(opened.bytes(), plaintext);
    // a changed byte of any later segment, the encrypted key included, is one error kind and draws entropy
    let mut parts: Vec<String> = token.as_str().split('.').map(str::to_owned).collect();
    let index = 1 + at % 4;
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
        let mut draws = Counter::new(seed, 0);
        let failed = Jwe::parse(&parts.join("."))
            .and_then(|jwe| jwe.decrypt_blinded::<K, E>(&decrypt, &mut draws));
        prop_assert_eq!(failed.err().map(|e| e.kind()), Some(ErrorKind::Decrypt));
        prop_assert!(draws.1 > 0);
    }
    Ok(())
}

#[test]
fn oaep_round_trip() {
    let mut keys = None;
    let tally = run::<Case>(vector!("rfc7516/jwe.json"), 1, |case| {
        if case.id == "a1-rsa-oaep-a256gcm-valid" {
            let secret =
                SecretJwk::decode(case.jwk.as_ref().map_or("{}", Json::text).as_bytes()).ok();
            keys = secret.as_ref().and_then(SecretJwk::public).zip(secret);
        }
        Outcome::Checked
    });
    assert_eq!(tally.checked(), tally.total());
    assert!(keys.is_some());
    let config = ProptestConfig {
        cases: 6,
        rng_seed: RngSeed::Fixed(0x5eed_0008),
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    let strategy = (
        proptest::collection::vec(any::<u8>(), 0..60),
        any::<u8>(),
        any::<usize>(),
    );
    let outcome = TestRunner::new(config).run(&strategy, |(payload, seed, at)| {
        if let Some(keys) = &keys {
            round::<RsaOaep, A256Gcm>(keys, &payload, seed, at)?;
            round::<RsaOaep256, A128CbcHs256>(keys, &payload, seed, at)?;
            round::<RsaOaep256, A256CbcHs512>(keys, &payload, seed, at)?;
        }
        Ok(())
    });
    assert_eq!(outcome, Ok(()));
}
