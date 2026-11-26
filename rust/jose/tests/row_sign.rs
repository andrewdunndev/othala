//! Issuing round trips (CONTRACT R42 to R45): sign then verify, `finish` of a signature equals `sign`, any one-byte
//! change fails, and the header's `kid` comes back.
use jose::{
    Alg, EdDsa, Es256, Es384, Header, Hs256, Jws, Kid, LocalAlg, SecretJwk, Signer, SigningKey,
    Unsigned, VerifyKey,
};
use proptest::prelude::*;
use proptest::test_runner::{RngSeed, TestRunner};
use serde::Deserialize;
use testkit::vector;
use testkit::vectors::{Json, Outcome, run, sections};

#[derive(Deserialize)]
struct Case {
    id: String,
    jwk: Option<Json>,
    private_jwk: Option<Json>,
}

fn case_key(file: testkit::vectors::Vector, id: Option<&str>, private: bool) -> String {
    let mut found = String::new();
    run::<Case>(file, 1, |case| {
        let json = if private {
            case.private_jwk.as_ref()
        } else {
            case.jwk.as_ref()
        };
        if found.is_empty() && id.is_none_or(|id| id == case.id) {
            found = json.map(|j| j.text().to_owned()).unwrap_or_default();
        }
        Outcome::Checked
    });
    found
}

struct Pair<A: LocalAlg> {
    signer: SigningKey<A>,
    verifier: VerifyKey<A>,
}

fn pair<A: LocalAlg>(jwk: &str) -> Option<Pair<A>> {
    let secret = SecretJwk::decode(jwk.as_bytes()).ok()?;
    Some(Pair {
        signer: secret.signing_key().ok()?,
        verifier: secret.verify_key().ok()?,
    })
}

fn round<A: LocalAlg>(
    pair: &Pair<A>,
    payload: &[u8],
    kid: &str,
    at: usize,
) -> Result<(), TestCaseError> {
    let header =
        || Kid::new(kid).map_or_else(|_| Header::<A>::new(), |kid| Header::new().with_kid(kid));
    let signed = Unsigned::<A>::jws(header(), payload).and_then(|u| u.sign(&pair.signer));
    prop_assert!(signed.is_ok());
    let token = signed.map_err(|_| TestCaseError::fail("sign"))?;
    // finish(signer.sign(signing_input)) is sign(signer)
    let unsigned = Unsigned::<A>::jws(header(), payload).map_err(|_| TestCaseError::fail("jws"))?;
    let signature = Signer::<A>::sign(&pair.signer, unsigned.signing_input())
        .map_err(|_| TestCaseError::fail("sig"))?;
    let finished = unsigned
        .finish(signature)
        .map_err(|_| TestCaseError::fail("finish"))?;
    prop_assert_eq!(finished.as_str(), token.as_str());
    // verify(sign(x)) is x, and the kid is the header's
    let parsed = Jws::parse(token.as_str()).map_err(|_| TestCaseError::fail("parse"))?;
    let want = Kid::new(kid).ok();
    prop_assert_eq!(parsed.kids().first(), want.as_ref());
    let verified = parsed
        .verify(&pair.verifier)
        .map_err(|_| TestCaseError::fail("verify"))?;
    prop_assert_eq!(verified.bytes(), payload);
    // any one-byte change fails
    let mut bytes = token.as_str().as_bytes().to_vec();
    let place = at % bytes.len();
    if let Some(byte) = bytes.get_mut(place).filter(|b| **b != b'.') {
        *byte = if *byte == b'A' { b'B' } else { b'A' };
        let changed = String::from_utf8(bytes).map_err(|_| TestCaseError::fail("utf8"))?;
        prop_assert!(
            Jws::parse(&changed)
                .and_then(|j| j.verify(&pair.verifier))
                .is_err()
        );
    }
    Ok(())
}

fn config(seed: u64) -> ProptestConfig {
    ProptestConfig {
        cases: 48,
        rng_seed: RngSeed::Fixed(seed),
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

#[test]
fn sign_round_trip() {
    let appendix_c = vector!("rfc7518/appendix-c.json");
    let p256 = pair::<Es256>(&case_key(appendix_c, Some("c-recipient"), true));
    let derived = case_key(
        vector!("jose-derived/thumbprint.json"),
        Some("ec-p384-private-members-ignored"),
        false,
    );
    // that key is published for encryption, so its `use` is dropped to sign with it
    let mut members: std::collections::BTreeMap<String, String> =
        serde_json::from_str(&derived).unwrap_or_default();
    members.remove("use");
    let p384 = pair::<Es384>(&serde_json::to_string(&members).unwrap_or_default());
    let okp = sections(vector!("rfc8037/appendix-a.json"));
    let ed = pair::<EdDsa>(
        okp.first()
            .and_then(|a| a.section.blocks.first())
            .map(|b| b.joined.as_str())
            .unwrap_or_default(),
    );
    let hs = pair::<Hs256>(&case_key(
        vector!("rfc7515/jws.json"),
        Some("a1-hs256-valid"),
        false,
    ));
    assert!(p256.is_some() && p384.is_some() && ed.is_some() && hs.is_some());
    let strategy = (
        proptest::collection::vec(any::<u8>(), 0..120),
        "[a-zA-Z0-9\"\\\\ /-]{0,24}",
        any::<usize>(),
    );
    let outcome = TestRunner::new(config(0x5eed_0004)).run(&strategy, |(payload, kid, at)| {
        if let Some(p) = &p256 {
            round(p, &payload, &kid, at)?;
        }
        if let Some(p) = &p384 {
            round(p, &payload, &kid, at)?;
        }
        if let Some(p) = &ed {
            round(p, &payload, &kid, at)?;
        }
        if let Some(p) = &hs {
            round(p, &payload, &kid, at)?;
        }
        Ok(())
    });
    assert!(outcome.is_ok(), "{outcome:?}");
}

#[cfg(feature = "es512")]
#[test]
fn sign_round_trip_p521() {
    let keys = testkit::vectors::figures(vector!("rfc7520/jwk.json"));
    let private = keys
        .examples
        .iter()
        .find(|e| e.example == "3.2")
        .and_then(|e| e.figures.last())
        .map(|f| f.joined.clone())
        .unwrap_or_default();
    let pair = pair::<jose::Es512>(&private);
    assert!(pair.is_some());
    let strategy = (
        proptest::collection::vec(any::<u8>(), 0..120),
        "[a-z]{0,12}",
        any::<usize>(),
    );
    let outcome = TestRunner::new(config(0x5eed_0005)).run(&strategy, |(payload, kid, at)| {
        if let Some(p) = &pair {
            round(p, &payload, &kid, at)?;
        }
        Ok(())
    });
    assert!(outcome.is_ok(), "{outcome:?}");
}

#[test]
fn alg_is_the_markers() {
    assert_eq!(
        (Header::<Es256>::new().alg(), Header::<Hs256>::new().alg()),
        (Es256::ALG, Hs256::ALG)
    );
}
