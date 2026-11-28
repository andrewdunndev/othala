//! RFC 7518 Appendix C: ECDH-ES derives the content-encryption key the RFC prints, from either side, and an
//! `epk` off its curve is refused before any agreement (CONTRACT R57).
use aes_gcm::aead::AeadInOut as _;
use aes_gcm::{Aes128Gcm, KeyInit as _};
use base::{b64url_decode, b64url_encode};
use jose::{A128Gcm, EcdhEs, Jwe, SecretJwk};
use serde::Deserialize;
use testkit::vector;
use testkit::vectors::{Json, Outcome, run};

#[derive(Deserialize)]
struct Expect {
    ok: bool,
    cek: Option<String>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    apu: String,
    apv: String,
    private_jwk: Json,
    public_jwk: Json,
    expect: Expect,
}

/// The EC public members of a JWK as an `epk` object.
fn epk(public: &Json) -> String {
    public.text().to_owned()
}

//= https://www.rfc-editor.org/rfc/rfc7518#section-4.6.1.3
//= type=test
//# This Header Parameter MUST be understood and processed by implementations when these algorithms
//# are used.
//= https://www.rfc-editor.org/rfc/rfc7518#section-4.6.1.2
//= type=test
//# This Header Parameter MUST be understood and processed by implementations when these algorithms
//# are used.
//= https://www.rfc-editor.org/rfc/rfc7518#section-4.6
//= type=test
//# In Direct Key Agreement mode, the output of the Concat KDF MUST be a key of the same length as
//# that used by the "enc" algorithm.
#[test]
fn appendix_c() {
    let tally = run::<Case>(vector!("rfc7518/appendix-c.json"), 3, |case| {
        // a JWE whose content key is the one the RFC prints; it decrypts only if the derivation reaches that key
        let cek = case
            .expect
            .cek
            .as_deref()
            .and_then(|c| b64url_decode(c).ok())
            .unwrap_or_else(|| vec![0; 16]);
        let header = format!(
            r#"{{"alg":"ECDH-ES","enc":"A128GCM","apu":"{}","apv":"{}","epk":{}}}"#,
            case.apu,
            case.apv,
            epk(&case.public_jwk)
        );
        let protected = b64url_encode(header.as_bytes());
        let (iv, mut body) = ([4_u8; 12], b"Hello".to_vec());
        let sealed = Aes128Gcm::new_from_slice(&cek).ok().and_then(|cipher| {
            cipher
                .encrypt_inout_detached(
                    &iv.into(),
                    protected.as_bytes(),
                    body.as_mut_slice().into(),
                )
                .ok()
        });
        let tag = sealed.map(|t| t.to_vec()).unwrap_or_default();
        let token = format!(
            "{protected}..{}.{}.{}",
            b64url_encode(&iv),
            b64url_encode(&body),
            b64url_encode(&tag)
        );
        let key = SecretJwk::decode(case.private_jwk.text().as_bytes())
            .and_then(|k| k.decrypt_key::<EcdhEs>());
        let opened = key.and_then(|key| Jwe::parse(&token)?.decrypt::<EcdhEs, A128Gcm>(&key));
        // a token the parser or a key check refuses is Malformed; one the decryption refuses is Decrypt
        assert_eq!(
            opened
                .as_ref()
                .err()
                .map(|e| e.kind() == jose::ErrorKind::Decrypt
                    || e.kind() == jose::ErrorKind::Malformed),
            (!case.expect.ok).then_some(true),
            "{}",
            case.id
        );
        if case.expect.ok {
            assert_eq!(
                opened.ok().map(|p| p.bytes().to_vec()),
                Some(b"Hello".to_vec()),
                "{}",
                case.id
            );
        }
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (3, 3));
}
