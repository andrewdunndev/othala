//! Wycheproof Ed25519 through `VerifyKey::verify_signature` (CONTRACT R6, R8); acceptable cases are not applicable.
use jose::{EdDsa, Jwk};
use testkit::vector;
use testkit::vectors::{Expected, Outcome, wycheproof};

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

#[test]
fn ed25519() {
    let tally = wycheproof(
        vector!("wycheproof/ed25519_test.json"),
        100,
        |group, case| {
            if case.result == Expected::Acceptable {
                return Outcome::NotApplicable;
            }
            let pk = group.public_key.as_ref().and_then(|k| k.pk.as_deref());
            let x = base::b64url_encode(&hex(pk.unwrap_or_default()));
            let jwk = format!(r#"{{"kty":"OKP","crv":"Ed25519","x":"{x}"}}"#);
            let key = Jwk::decode(jwk.as_bytes()).and_then(|jwk| jwk.verify_key::<EdDsa>());
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
        },
    );
    assert_eq!((tally.total(), tally.checked()), (210, 181));
}
