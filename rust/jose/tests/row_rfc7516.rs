//! RFC 7516 Appendix A.3, the header refusals and issuing round trips (CONTRACT R48, R51 to R53, R59).
mod common_jwe;

use base::{Entropy, SecretBytes, b64url_decode, b64url_encode};
use jose::{
    A128CbcHs256, A128Gcm, A128GcmKw, A128Kw, A192CbcHs384, A192Gcm, A192GcmKw, A192Kw,
    A256CbcHs512, A256Gcm, A256GcmKw, A256Kw, Dir, Enc, ErrorKind, Jwe, JweAlg, KeyAlg,
    LocalKeyAlg, SecretJwk,
};
use proptest::prelude::*;
use proptest::test_runner::{RngSeed, TestRunner};
use serde::Deserialize;
use testkit::vector;
use testkit::vectors::{Json, Outcome, Vector, run};

#[derive(Deserialize)]
struct Expect {
    ok: bool,
    plaintext: Option<String>,
    kind: Option<String>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    alg: String,
    enc: String,
    jwk: Option<Json>,
    jwe: String,
    expect: Expect,
}

/// Runs a file of compact `jwe_decrypt` cases: the algorithms this item owns decrypt or are refused as the vector
/// says; ECDH-ES, RSA-OAEP and key types of later items are counted not applicable by name.
fn row(file: Vector, total: usize, applicable: usize) {
    let tally = run::<Case>(file, 1, |case| {
        let owned = common_jwe::LOCAL.contains(&case.alg.as_str());
        let refused = ["RSA1_5", "PBES2-HS512+A256KW"].contains(&case.alg.as_str());
        if !owned && !refused && !case.id.contains("zip") {
            return Outcome::NotApplicable;
        }
        if case.alg.starts_with("ECDH") || case.alg.starts_with("RSA-OAEP") {
            return Outcome::NotApplicable;
        }
        let jwk = case.jwk.as_ref().map_or("{}", Json::text);
        let outcomes: Vec<Result<Vec<u8>, jose::Error>> = if refused {
            common_jwe::LOCAL
                .iter()
                .map(|alg| common_jwe::decrypt(alg, &case.enc, jwk, Jwe::parse(&case.jwe)?))
                .collect()
        } else {
            vec![
                Jwe::parse(&case.jwe)
                    .and_then(|jwe| common_jwe::decrypt(&case.alg, &case.enc, jwk, jwe)),
            ]
        };
        if refused {
            assert!(outcomes.iter().all(Result::is_err), "{}", case.id);
            assert_eq!(
                JweAlg::parse(&case.alg).err().map(|e| e.kind()),
                Some(ErrorKind::UnsupportedAlg)
            );
            return Outcome::Checked;
        }
        let outcome = outcomes
            .into_iter()
            .next()
            .unwrap_or(Err(ErrorKind::Malformed.into()));
        assert_eq!(outcome.is_ok(), case.expect.ok, "{}", case.id);
        if let Some(want) = &case.expect.plaintext {
            assert_eq!(
                outcome.as_ref().ok().map(|p| b64url_encode(p)).as_ref(),
                Some(want),
                "{}",
                case.id
            );
        }
        if let Some(kind) = &case.expect.kind {
            assert_eq!(
                outcome.err().map(|e| format!("{:?}", e.kind())).as_ref(),
                Some(kind),
                "{}",
                case.id
            );
        }
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (total, applicable));
}

#[test]
fn rfc7516_appendix_a() {
    row(vector!("rfc7516/jwe.json"), 13, 7);
}

#[test]
fn header_cases() {
    row(vector!("jose-derived/jwe-header.json"), 11, 10);
}

fn key<K: KeyAlg>(len: usize) -> Option<(jose::EncryptKey<K>, SecretJwk)> {
    let bytes: Vec<u8> = (0..len)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect();
    let enc = SecretJwk::from_oct(SecretBytes::new(bytes.clone()))
        .encrypt_key::<K>()
        .ok()?;
    Some((enc, SecretJwk::from_oct(SecretBytes::new(bytes))))
}

/// A counter standing in for entropy: one seed is one token.
struct Counter(u8);

impl Entropy for Counter {
    fn fill(&mut self, out: &mut [u8]) {
        for byte in out {
            self.0 = self.0.wrapping_mul(31).wrapping_add(7);
            *byte = self.0;
        }
    }
}

fn cek_len(enc: &str) -> usize {
    match enc {
        "A128GCM" => 16,
        "A192GCM" => 24,
        "A256GCM" | "A128CBC-HS256" => 32,
        "A192CBC-HS384" => 48,
        _ => 64,
    }
}

/// `decrypt(encrypt(x)) = x`, one seed gives one token, and a changed byte of any later segment is `Decrypt`.
fn round<K: LocalKeyAlg, E: Enc>(
    len: usize,
    plaintext: &[u8],
    seed: u8,
    at: usize,
) -> Result<(), TestCaseError> {
    let (encrypt, secret) = key::<K>(len).ok_or_else(|| TestCaseError::fail("key"))?;
    let decrypt = secret
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
        let changed = parts.join(".");
        let failed = Jwe::parse(&changed).and_then(|jwe| jwe.decrypt::<K, E>(&decrypt));
        prop_assert_eq!(failed.err().map(|e| e.kind()), Some(ErrorKind::Decrypt));
    }
    Ok(())
}

macro_rules! all_enc {
    ($key:ty, $len:expr, $payload:expr, $seed:expr, $at:expr) => {{
        round::<$key, A128Gcm>($len.unwrap_or(16), $payload, $seed, $at)?;
        round::<$key, A192Gcm>($len.unwrap_or(24), $payload, $seed, $at)?;
        round::<$key, A256Gcm>($len.unwrap_or(32), $payload, $seed, $at)?;
        round::<$key, A128CbcHs256>($len.unwrap_or(32), $payload, $seed, $at)?;
        round::<$key, A192CbcHs384>($len.unwrap_or(48), $payload, $seed, $at)?;
        round::<$key, A256CbcHs512>($len.unwrap_or(64), $payload, $seed, $at)?;
    }};
}

#[test]
fn jwe_round_trip() {
    let config = ProptestConfig {
        cases: 24,
        rng_seed: RngSeed::Fixed(0x5eed_0006),
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    let strategy = (
        proptest::collection::vec(any::<u8>(), 0..80),
        any::<u8>(),
        any::<usize>(),
    );
    let outcome = TestRunner::new(config).run(&strategy, |(payload, seed, at)| {
        all_enc!(A128Kw, Some(16), &payload, seed, at);
        all_enc!(A192Kw, Some(24), &payload, seed, at);
        all_enc!(A256Kw, Some(32), &payload, seed, at);
        all_enc!(A128GcmKw, Some(16), &payload, seed, at);
        all_enc!(A192GcmKw, Some(24), &payload, seed, at);
        all_enc!(A256GcmKw, Some(32), &payload, seed, at);
        all_enc!(Dir, None::<usize>, &payload, seed, at);
        Ok(())
    });
    assert!(outcome.is_ok(), "{outcome:?}");
    assert_eq!(cek_len("A128GCM"), 16);
}
