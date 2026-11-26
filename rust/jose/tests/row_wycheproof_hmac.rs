//! Wycheproof HMAC through `VerifyKey::verify_signature` (CONTRACT R6, R13).
use base::SecretBytes;
use jose::{Alg, ErrorKind, Hs256, Hs384, Hs512, SecretJwk};
use testkit::vector;
use testkit::vectors::{Expected, Outcome, Vector, wycheproof};

fn hex(text: &str) -> Vec<u8> {
    let bytes: Vec<u8> = text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .filter_map(|pair| {
            let pair = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect();
    assert_eq!(bytes.len() * 2, text.len(), "{text}");
    bytes
}

/// Every case of `file`: a key shorter than the hash is `WeakKey` and not applicable, a full-length tag of a valid
/// case verifies, and every other case (an invalid tag, a truncated tag) is refused.
fn row<A: Alg>(file: Vector, hash_bits: u32, checked: usize) {
    let tally = wycheproof(file, 100, |group, case| {
        let key = hex(case.key.as_deref().unwrap_or_default());
        let jwk = SecretJwk::from_oct(SecretBytes::new(key));
        let verifier = jwk.verify_key::<A>();
        if group.key_size.is_some_and(|bits| bits < hash_bits) {
            assert_eq!(
                verifier.err().map(|e| e.kind()),
                Some(ErrorKind::WeakKey),
                "{}",
                case.tc_id
            );
            return Outcome::NotApplicable;
        }
        let message = hex(case.msg.as_deref().unwrap_or_default());
        let tag = hex(case.tag.as_deref().unwrap_or_default());
        let outcome = verifier.and_then(|key| key.verify_signature(&message, &tag));
        let full = group.tag_size == Some(hash_bits);
        match (case.result, full) {
            (Expected::Valid, true) => assert!(outcome.is_ok(), "{}: {}", case.tc_id, case.comment),
            (Expected::Acceptable, _) => return Outcome::NotApplicable,
            _ => assert_eq!(
                outcome.err().map(|e| e.kind()),
                Some(ErrorKind::BadSignature),
                "{}: {}",
                case.tc_id,
                case.comment
            ),
        }
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (174, checked));
}

#[test]
fn hmac_sha256() {
    row::<Hs256>(vector!("wycheproof/hmac_sha256_test.json"), 256, 168);
}

#[test]
fn hmac_sha384() {
    row::<Hs384>(vector!("wycheproof/hmac_sha384_test.json"), 384, 168);
}

#[test]
fn hmac_sha512() {
    row::<Hs512>(vector!("wycheproof/hmac_sha512_test.json"), 512, 168);
}
