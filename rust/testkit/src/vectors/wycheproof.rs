//! Wycheproof files: `testGroups[].tests`, each case visited once and reported once.
use std::collections::BTreeSet;

use serde::Deserialize;

use super::{Outcome, SOURCES, Tally, Vector, floored, verified};

/// What Wycheproof says the case must do.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Expected {
    /// The input is well formed and must be accepted.
    Valid,
    /// The input must be refused.
    Invalid,
    /// Either answer is defensible; the case's flags say why.
    Acceptable,
}

/// A JWK as a group publishes it.
#[derive(Clone, Debug, Deserialize)]
pub struct Jwk {
    /// `kty`.
    pub kty: String,
    /// `kid`.
    pub kid: Option<String>,
    /// `alg`.
    pub alg: Option<String>,
    /// `crv`.
    pub crv: Option<String>,
    /// `x`.
    pub x: Option<String>,
    /// `y`.
    pub y: Option<String>,
    /// `n`.
    pub n: Option<String>,
    /// `e`.
    pub e: Option<String>,
}

/// The group's `publicKey` object; each key type fills only its own fields (hex, as Wycheproof writes them).
#[derive(Clone, Debug, Deserialize)]
pub struct KeyMaterial {
    /// EC curve name.
    pub curve: Option<String>,
    /// EC point, uncompressed.
    pub uncompressed: Option<String>,
    /// EC affine x.
    pub wx: Option<String>,
    /// EC affine y.
    pub wy: Option<String>,
    /// EdDSA public key.
    pub pk: Option<String>,
    /// RSA modulus.
    pub modulus: Option<String>,
    /// RSA public exponent.
    #[serde(rename = "publicExponent")]
    pub public_exponent: Option<String>,
}

/// A test group's parameters and key material.
#[derive(Clone, Debug, Deserialize)]
pub struct Group {
    /// The group `type`, such as `EcdsaVerify`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The `publicKey` object.
    #[serde(rename = "publicKey")]
    pub public_key: Option<KeyMaterial>,
    /// `publicKeyJwk`.
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: Option<Jwk>,
    /// `keyJwk` (the RSA PKCS#1 files name their JWK this way).
    #[serde(rename = "keyJwk")]
    pub key_jwk: Option<Jwk>,
    /// `publicKeyDer`, hex.
    #[serde(rename = "publicKeyDer")]
    pub public_key_der: Option<String>,
    /// `publicKeyPem`.
    #[serde(rename = "publicKeyPem")]
    pub public_key_pem: Option<String>,
    /// `publicKeyAsn`, hex.
    #[serde(rename = "publicKeyAsn")]
    pub public_key_asn: Option<String>,
    /// `sha`, such as `SHA-256`.
    pub sha: Option<String>,
    /// `mgf`.
    pub mgf: Option<String>,
    /// `mgfSha`.
    #[serde(rename = "mgfSha")]
    pub mgf_sha: Option<String>,
    /// `sLen`, the PSS salt length.
    #[serde(rename = "sLen")]
    pub s_len: Option<u32>,
    /// `keySize`, in bits.
    #[serde(rename = "keySize")]
    pub key_size: Option<u32>,
    /// `tagSize`, in bits.
    #[serde(rename = "tagSize")]
    pub tag_size: Option<u32>,
    tests: Vec<Test>,
}

/// One Wycheproof test case; hex fields stay hex.
#[derive(Clone, Debug, Deserialize)]
pub struct Test {
    /// `tcId`, unique in the file.
    #[serde(rename = "tcId")]
    pub tc_id: u32,
    /// `comment`.
    pub comment: String,
    /// `flags`.
    pub flags: Vec<String>,
    /// `result`.
    pub result: Expected,
    /// `msg`.
    pub msg: Option<String>,
    /// `sig`.
    pub sig: Option<String>,
    /// `key` (MAC files carry the key per case).
    pub key: Option<String>,
    /// `tag`.
    pub tag: Option<String>,
}

#[derive(Deserialize)]
struct File {
    #[serde(rename = "numberOfTests")]
    number_of_tests: usize,
    #[serde(rename = "testGroups")]
    test_groups: Vec<Group>,
}

/// Runs `check` over every case of a Wycheproof `vector`; each call reports one [`Outcome`]. Panics unless the file has
/// the SHA-256 `SOURCES.toml` lists, its `numberOfTests`, the declared cases and the cases visited agree, every
/// `tcId` is unique, and at least `floor` (nonzero) were checked.
pub fn wycheproof(
    vector: Vector,
    floor: usize,
    check: impl FnMut(&Group, &Test) -> Outcome,
) -> Tally {
    wycheproof_against(SOURCES, vector, floor, check)
}

fn wycheproof_against(
    sources: &str,
    vector: Vector,
    floor: usize,
    mut check: impl FnMut(&Group, &Test) -> Outcome,
) -> Tally {
    let path = vector.path;
    let declared = verified(sources, vector);
    let file: File = serde_json::from_str(vector.json).expect("vector file decodes");
    assert_eq!(
        file.number_of_tests, declared,
        "{path}: numberOfTests against SOURCES.toml"
    );
    let (mut visited, mut checked) = (0_usize, 0_usize);
    let mut ids = BTreeSet::new();
    for group in &file.test_groups {
        for test in &group.tests {
            assert!(
                ids.insert(test.tc_id),
                "{path}: tcId {} appears twice",
                test.tc_id
            );
            visited += 1;
            if check(group, test) == Outcome::Checked {
                checked += 1;
            }
        }
    }
    assert_eq!(
        visited, file.number_of_tests,
        "{path}: cases visited against numberOfTests"
    );
    floored(path, visited, checked, floor)
}

#[cfg(test)]
mod tests {
    use super::{Expected, wycheproof, wycheproof_against};
    use crate::vectors::{Outcome, Vector};

    const SOURCES: &str = r#"
[source."w"]
files = [ { path = "w/t.json", sha256 = "SHA", cases = 2 } ]
"#;

    fn sources_for(json: &str) -> String {
        use sha2::{Digest as _, Sha256};
        let sha: String = Sha256::digest(json)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        SOURCES.replace("SHA", &sha)
    }

    const TWO: &str = r#"{ "numberOfTests": 2, "testGroups": [
      { "type": "MacTest", "tests": [
        { "tcId": 1, "comment": "a", "flags": [], "result": "valid", "key": "00" },
        { "tcId": 2, "comment": "b", "flags": ["F"], "result": "acceptable" } ] } ] }"#;

    #[test]
    fn visits_every_case_once() {
        let mut seen = Vec::new();
        let t = wycheproof_against(
            &sources_for(TWO),
            Vector::new("w/t.json", TWO),
            1,
            |g, c| {
                seen.push((g.kind.clone(), c.tc_id, c.result));
                if c.key.is_some() {
                    Outcome::Checked
                } else {
                    Outcome::NotApplicable
                }
            },
        );
        assert_eq!((t.total(), t.checked(), t.not_applicable()), (2, 1, 1));
        assert_eq!(
            seen,
            [
                ("MacTest".to_owned(), 1, Expected::Valid),
                ("MacTest".to_owned(), 2, Expected::Acceptable)
            ]
        );
    }

    const THREE_DECLARED: &str = r#"{ "numberOfTests": 3, "testGroups": [] }"#;
    const ONE_PRESENT: &str = r#"{ "numberOfTests": 2, "testGroups": [
      { "type": "MacTest", "tests": [
        { "tcId": 1, "comment": "a", "flags": [], "result": "valid" } ] } ] }"#;
    const DUPLICATE: &str = r#"{ "numberOfTests": 2, "testGroups": [
      { "type": "MacTest", "tests": [
        { "tcId": 1, "comment": "a", "flags": [], "result": "valid" },
        { "tcId": 1, "comment": "b", "flags": [], "result": "invalid" } ] } ] }"#;

    fn all(json: &'static str) {
        wycheproof_against(
            &sources_for(json),
            Vector::new("w/t.json", json),
            1,
            |_, _| Outcome::Checked,
        );
    }

    #[test]
    #[should_panic(expected = "numberOfTests against SOURCES.toml")]
    fn number_of_tests_must_match_sources() {
        all(THREE_DECLARED);
    }

    #[test]
    #[should_panic(expected = "cases visited against numberOfTests")]
    fn visited_must_match_number_of_tests() {
        all(ONE_PRESENT);
    }

    #[test]
    #[should_panic(expected = "tcId 1 appears twice")]
    fn tc_id_is_unique() {
        all(DUPLICATE);
    }

    #[test]
    #[should_panic(expected = "SHA-256 of the file against SOURCES.toml")]
    fn altered_file_fails_before_parsing() {
        let sources = sources_for(TWO);
        wycheproof_against(&sources, Vector::new("w/t.json", "not json"), 1, |_, _| {
            Outcome::Checked
        });
    }

    macro_rules! files {
        ($($path:literal => $n:literal,)*) => {
            [$((crate::vector!($path), $n)),*]
        };
    }

    // every Wycheproof file in rust/vectors with the numberOfTests it declares
    fn every_file() -> [(Vector, usize); 23] {
        files! {
        "wycheproof/ecdsa_secp256r1_sha256_p1363_test.json" => 262,
        "wycheproof/ecdsa_secp256r1_sha256_test.json" => 484,
        "wycheproof/ecdsa_secp384r1_sha384_p1363_test.json" => 280,
        "wycheproof/ecdsa_secp384r1_sha384_test.json" => 504,
        "wycheproof/ed25519_test.json" => 210,
        "wycheproof/hmac_sha256_test.json" => 174,
        "wycheproof/hmac_sha384_test.json" => 174,
        "wycheproof/hmac_sha512_test.json" => 174,
        "wycheproof/rsa_pss_2048_sha256_mgf1_32_test.json" => 108,
        "wycheproof/rsa_pss_2048_sha384_mgf1_48_test.json" => 141,
        "wycheproof/rsa_pss_3072_sha256_mgf1_32_test.json" => 108,
        "wycheproof/rsa_pss_4096_sha256_mgf1_32_test.json" => 108,
        "wycheproof/rsa_pss_4096_sha384_mgf1_48_test.json" => 141,
        "wycheproof/rsa_pss_4096_sha512_mgf1_64_test.json" => 179,
        "wycheproof/rsa_signature_2048_sha256_test.json" => 259,
        "wycheproof/rsa_signature_2048_sha384_test.json" => 258,
        "wycheproof/rsa_signature_2048_sha512_test.json" => 259,
        "wycheproof/rsa_signature_3072_sha256_test.json" => 259,
        "wycheproof/rsa_signature_3072_sha384_test.json" => 259,
        "wycheproof/rsa_signature_3072_sha512_test.json" => 260,
        "wycheproof/rsa_signature_4096_sha256_test.json" => 258,
        "wycheproof/rsa_signature_4096_sha384_test.json" => 259,
        "wycheproof/rsa_signature_4096_sha512_test.json" => 259,
        }
    }

    #[test]
    fn every_file_is_visited_whole_and_reports_each_case_once() {
        let (mut total, mut counts) = (0, [0_usize; 3]);
        for (vector, declared) in every_file() {
            let t = wycheproof(vector, 1, |_, c| {
                let slot = match c.result {
                    Expected::Valid => 0,
                    Expected::Invalid => 1,
                    Expected::Acceptable => 2,
                };
                if let Some(n) = counts.get_mut(slot) {
                    *n += 1;
                }
                Outcome::Checked
            });
            assert_eq!(
                (t.total(), t.checked(), t.not_applicable()),
                (declared, declared, 0)
            );
            total += t.total();
        }
        assert_eq!(total, 5377);
        assert_eq!(counts, [1628, 3711, 38]);
    }

    #[test]
    fn every_group_carries_its_key_material() {
        for (vector, _) in every_file() {
            wycheproof(vector, 1, |g, c| {
                let keyed = g.public_key_jwk.is_some()
                    || g.key_jwk.is_some()
                    || g.public_key_der.is_some()
                    || g.public_key.is_some()
                    || c.key.is_some();
                assert!(keyed, "tcId {} of {} has no key", c.tc_id, g.kind);
                Outcome::Checked
            });
        }
    }
}
