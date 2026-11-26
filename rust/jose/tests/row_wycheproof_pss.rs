//! Wycheproof RSASSA-PSS (salt the hash length) through `VerifyKey::verify_signature` (CONTRACT R6); acceptable cases are not applicable.
use jose::{Jwk, Ps256, Ps384, Ps512, PublicAlg};
use testkit::vector;
use testkit::vectors::{Expected, Outcome, Vector, wycheproof};

fn hex(text: &str) -> Vec<u8> {
    let parse = |pair: &[u8; 2]| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok();
    let bytes: Vec<u8> = text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .filter_map(parse)
        .collect();
    assert_eq!(bytes.len() * 2, text.len(), "{text}");
    bytes
}

fn row<A: PublicAlg>(file: Vector, total: usize) {
    let tally = wycheproof(file, 100, |group, case| {
        if case.result == Expected::Acceptable {
            return Outcome::NotApplicable;
        }
        let jwk = group.public_key_jwk.as_ref();
        let member = |text: Option<&String>| text.cloned().unwrap_or_default();
        let json = format!(
            r#"{{"kty":"RSA","n":"{}","e":"{}"}}"#,
            member(jwk.and_then(|k| k.n.as_ref())),
            member(jwk.and_then(|k| k.e.as_ref()))
        );
        let key = Jwk::decode(json.as_bytes()).and_then(|jwk| jwk.verify_key::<A>());
        assert!(key.is_ok(), "{}", case.tc_id);
        let message = hex(case.msg.as_deref().unwrap_or_default());
        let signature = hex(case.sig.as_deref().unwrap_or_default());
        let outcome = key.and_then(|key| key.verify_signature(&message, &signature));
        assert_eq!(
            outcome.is_ok(),
            case.result == Expected::Valid,
            "{}: {}",
            case.tc_id,
            case.comment
        );
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (total, total));
}

#[test]
fn ps256() {
    row::<Ps256>(
        vector!("wycheproof/rsa_pss_2048_sha256_mgf1_32_test.json"),
        108,
    );
    row::<Ps256>(
        vector!("wycheproof/rsa_pss_3072_sha256_mgf1_32_test.json"),
        108,
    );
    row::<Ps256>(
        vector!("wycheproof/rsa_pss_4096_sha256_mgf1_32_test.json"),
        108,
    );
}

#[test]
fn ps384() {
    row::<Ps384>(
        vector!("wycheproof/rsa_pss_2048_sha384_mgf1_48_test.json"),
        141,
    );
    row::<Ps384>(
        vector!("wycheproof/rsa_pss_4096_sha384_mgf1_48_test.json"),
        141,
    );
}

#[test]
fn ps512() {
    row::<Ps512>(
        vector!("wycheproof/rsa_pss_4096_sha512_mgf1_64_test.json"),
        179,
    );
}
