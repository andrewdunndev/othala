//! RS and PS signing through the blinded path (CONTRACT R45, R46): RFC 7520 4.1 reproduced byte for byte, every RS and
//! PS algorithm round trips, and the entropy is drawn from.
#![cfg(feature = "rsa-sign")]

mod common_figures;

use base::Entropy;
use jose::{
    BlindedAlg, Header, Jws, Kid, Ps256, Ps384, Ps512, Rs256, Rs384, Rs512, SecretJwk, Unsigned,
};
use proptest::prelude::*;
use proptest::test_runner::{RngSeed, TestRunner};
use testkit::vector;
use testkit::vectors::Figures;

/// Seeded entropy that counts its draws.
struct Draws(testkit::Seeded, usize);

impl Entropy for Draws {
    fn fill(&mut self, out: &mut [u8]) {
        self.1 += 1;
        self.0.fill(out);
    }
}

fn figure(file: &Figures, example: &str, number: u32) -> String {
    let found = file.examples.iter().find(|e| e.example == example);
    found
        .and_then(|e| e.figures.iter().find(|f| f.figure == number))
        .map(|f| f.joined.clone())
        .unwrap_or_default()
}

fn key() -> Option<SecretJwk> {
    let keys = common_figures::all(vector!("rfc7520/jwk.json"));
    let found = keys.examples.iter().find(|e| e.example == "3.4");
    let json = found
        .and_then(|e| e.figures.last())
        .and_then(|f| f.json.as_ref());
    SecretJwk::decode(json.map_or("", |j| j.text()).as_bytes()).ok()
}

#[test]
fn rfc7520_4_1_byte_for_byte() {
    let signed = common_figures::all(vector!("rfc7520/jws.json"));
    let token = figure(&signed, "4.1", 13);
    let payload = token
        .split('.')
        .nth(1)
        .and_then(|p| base::b64url_decode(p).ok())
        .unwrap_or_default();
    let kid = Kid::new("bilbo.baggins@hobbiton.example").ok();
    let secret = key();
    let signer = secret.as_ref().and_then(|k| k.signing_key::<Rs256>().ok());
    let mut draws = Draws(testkit::seeded(1), 0);
    let issued = signer.zip(kid).and_then(|(signer, kid)| {
        Unsigned::<Rs256>::jws(Header::new().with_kid(kid), &payload)
            .ok()?
            .sign_blinded(&signer, &mut draws)
            .ok()
    });
    assert_eq!(issued.as_ref().map(|t| t.as_str()), Some(token.as_str()));
    assert!(draws.1 > 0);
}

fn round<A: BlindedAlg>(
    secret: &SecretJwk,
    payload: &[u8],
    seed: u8,
    at: usize,
) -> Result<(), TestCaseError> {
    let signer = secret
        .signing_key::<A>()
        .map_err(|_| TestCaseError::fail("signing key"))?;
    let verifier = secret
        .verify_key::<A>()
        .map_err(|_| TestCaseError::fail("verify key"))?;
    let mut draws = Draws(testkit::seeded(u64::from(seed)), 0);
    let token = Unsigned::<A>::jws(Header::new(), payload)
        .and_then(|u| u.sign_blinded(&signer, &mut draws))
        .map_err(|_| TestCaseError::fail("sign"))?;
    prop_assert!(draws.1 > 0);
    let verified = Jws::parse(token.as_str())
        .and_then(|j| j.verify(&verifier))
        .map_err(|_| TestCaseError::fail("verify"))?;
    prop_assert_eq!(verified.bytes(), payload);
    let mut bytes = token.as_str().as_bytes().to_vec();
    let place = at % bytes.len();
    if let Some(byte) = bytes.get_mut(place).filter(|b| **b != b'.') {
        *byte = if *byte == b'A' { b'B' } else { b'A' };
        let changed = String::from_utf8(bytes).map_err(|_| TestCaseError::fail("utf8"))?;
        prop_assert!(
            Jws::parse(&changed)
                .and_then(|j| j.verify(&verifier))
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn every_rs_and_ps_round_trips() {
    let secret = key();
    assert!(secret.is_some());
    let config = ProptestConfig {
        cases: 4,
        rng_seed: RngSeed::Fixed(0x5eed_0009),
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    let strategy = (
        proptest::collection::vec(any::<u8>(), 0..60),
        any::<u8>(),
        any::<usize>(),
    );
    let outcome = TestRunner::new(config).run(&strategy, |(payload, seed, at)| {
        if let Some(secret) = &secret {
            round::<Rs256>(secret, &payload, seed, at)?;
            round::<Rs384>(secret, &payload, seed, at)?;
            round::<Rs512>(secret, &payload, seed, at)?;
            round::<Ps256>(secret, &payload, seed, at)?;
            round::<Ps384>(secret, &payload, seed, at)?;
            round::<Ps512>(secret, &payload, seed, at)?;
        }
        Ok(())
    });
    assert!(outcome.is_ok(), "{outcome:?}");
}
