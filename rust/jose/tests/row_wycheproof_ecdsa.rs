//! Wycheproof ECDSA through `VerifyKey::verify_signature` (CONTRACT R6, R7); ES512 is in `row_es512`.
use jose::{Es256, Es384, Jwk, PublicAlg};
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

/// `p1363` files: a valid case verifies and an invalid one is refused; the DER files hold no signature this
/// crate accepts, valid ones included.
fn row<A: PublicAlg>(file: Vector, curve: &str, size: usize, p1363: bool, total: usize) {
    let tally = wycheproof(file, 100, |group, case| {
        let point = hex(group
            .public_key
            .as_ref()
            .and_then(|k| k.uncompressed.as_deref())
            .unwrap_or_default());
        assert_eq!(point.len(), 1 + 2 * size);
        let coordinate = |range: std::ops::Range<usize>| {
            base::b64url_encode(point.get(range).unwrap_or_default())
        };
        let jwk = format!(
            r#"{{"kty":"EC","crv":"{curve}","x":"{}","y":"{}"}}"#,
            coordinate(1..1 + size),
            coordinate(1 + size..1 + 2 * size)
        );
        let key = Jwk::decode(jwk.as_bytes()).and_then(|jwk| jwk.verify_key::<A>());
        assert_eq!(key.as_ref().err().map(|e| e.kind()), None, "{}", case.tc_id);
        let message = hex(case.msg.as_deref().unwrap_or_default());
        let signature = hex(case.sig.as_deref().unwrap_or_default());
        let outcome = key.and_then(|key| key.verify_signature(&message, &signature));
        match (p1363, case.result) {
            (_, Expected::Acceptable) => return Outcome::NotApplicable,
            (true, Expected::Valid) => assert_eq!(
                outcome.err().map(|e| e.kind()),
                None,
                "{}: {}",
                case.tc_id,
                case.comment
            ),
            _ => assert_eq!(
                outcome.err().map(|e| e.kind()),
                Some(jose::ErrorKind::BadSignature),
                "{}: {}",
                case.tc_id,
                case.comment
            ),
        }
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (total, total));
}

#[test]
fn p256_p1363() {
    row::<Es256>(
        vector!("wycheproof/ecdsa_secp256r1_sha256_p1363_test.json"),
        "P-256",
        32,
        true,
        262,
    );
}

#[test]
fn p256_der_is_refused() {
    row::<Es256>(
        vector!("wycheproof/ecdsa_secp256r1_sha256_test.json"),
        "P-256",
        32,
        false,
        484,
    );
}

#[test]
fn p384_p1363() {
    row::<Es384>(
        vector!("wycheproof/ecdsa_secp384r1_sha384_p1363_test.json"),
        "P-384",
        48,
        true,
        280,
    );
}

#[test]
fn p384_der_is_refused() {
    row::<Es384>(
        vector!("wycheproof/ecdsa_secp384r1_sha384_test.json"),
        "P-384",
        48,
        false,
        504,
    );
}
