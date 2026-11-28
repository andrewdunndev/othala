//! Wycheproof RSASSA-PKCS1-v1_5 through `VerifyKey::verify_signature` (CONTRACT R6); acceptable cases are not applicable.
use jose::{Jwk, PublicAlg, Rs256, Rs384, Rs512};
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
        let jwk = group.key_jwk.as_ref();
        let member = |text: Option<&String>| text.cloned().unwrap_or_default();
        let json = format!(
            r#"{{"kty":"RSA","n":"{}","e":"{}"}}"#,
            member(jwk.and_then(|k| k.n.as_ref())),
            member(jwk.and_then(|k| k.e.as_ref()))
        );
        let key = Jwk::decode(json.as_bytes()).and_then(|jwk| jwk.verify_key::<A>());
        assert_eq!(key.as_ref().err().map(|e| e.kind()), None, "{}", case.tc_id);
        let message = hex(case.msg.as_deref().unwrap_or_default());
        let signature = hex(case.sig.as_deref().unwrap_or_default());
        let outcome = key.and_then(|key| key.verify_signature(&message, &signature));
        assert_eq!(
            outcome.err().map(|e| e.kind()),
            (case.result != Expected::Valid).then_some(jose::ErrorKind::BadSignature),
            "{}: {}",
            case.tc_id,
            case.comment
        );
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.not_applicable()), (total, 1));
}

#[test]
fn rs256() {
    row::<Rs256>(
        vector!("wycheproof/rsa_signature_2048_sha256_test.json"),
        259,
    );
    row::<Rs256>(
        vector!("wycheproof/rsa_signature_3072_sha256_test.json"),
        259,
    );
    row::<Rs256>(
        vector!("wycheproof/rsa_signature_4096_sha256_test.json"),
        258,
    );
}

#[test]
fn rs384() {
    row::<Rs384>(
        vector!("wycheproof/rsa_signature_2048_sha384_test.json"),
        258,
    );
    row::<Rs384>(
        vector!("wycheproof/rsa_signature_3072_sha384_test.json"),
        259,
    );
    row::<Rs384>(
        vector!("wycheproof/rsa_signature_4096_sha384_test.json"),
        259,
    );
}

#[test]
fn rs512() {
    row::<Rs512>(
        vector!("wycheproof/rsa_signature_2048_sha512_test.json"),
        259,
    );
    row::<Rs512>(
        vector!("wycheproof/rsa_signature_3072_sha512_test.json"),
        260,
    );
    row::<Rs512>(
        vector!("wycheproof/rsa_signature_4096_sha512_test.json"),
        259,
    );
}
