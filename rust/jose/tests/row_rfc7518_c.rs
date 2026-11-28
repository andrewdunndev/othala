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

/// A compact ECDH-ES JWE whose header is `header`, its content sealed under `cek` (A128GCM, IV `[4; 12]`).
fn sealed_under(header: &str, cek: &[u8]) -> String {
    let protected = b64url_encode(header.as_bytes());
    let (iv, mut body) = ([4_u8; 12], b"Hello".to_vec());
    let tag = Aes128Gcm::new_from_slice(cek)
        .ok()
        .and_then(|cipher| {
            cipher
                .encrypt_inout_detached(
                    &iv.into(),
                    protected.as_bytes(),
                    body.as_mut_slice().into(),
                )
                .ok()
        })
        .map(|t| t.to_vec())
        .unwrap_or_default();
    format!(
        "{protected}..{}.{}.{}",
        b64url_encode(&iv),
        b64url_encode(&body),
        b64url_encode(&tag)
    )
}

//= https://www.rfc-editor.org/rfc/rfc7518#section-4.6.1.1
//= type=test
//# This Header Parameter MUST be present and MUST be understood and processed by
//# implementations when these algorithms are used.
#[test]
fn epk_must_be_present() {
    let tally = run::<Case>(vector!("rfc7518/appendix-c.json"), 1, |case| {
        if case.id != "c-recipient" {
            return Outcome::NotApplicable;
        }
        let cek = case
            .expect
            .cek
            .as_deref()
            .and_then(|c| b64url_decode(c).ok())
            .unwrap_or_default();
        let key = SecretJwk::decode(case.private_jwk.text().as_bytes())
            .and_then(|k| k.decrypt_key::<EcdhEs>());
        let open = |token: &str| {
            key.as_ref()
                .map_err(|e| e.kind())
                .and_then(|k| {
                    Jwe::parse(token)
                        .and_then(|jwe| jwe.decrypt::<EcdhEs, A128Gcm>(k))
                        .map_err(|e| e.kind())
                })
                .map(|p| p.bytes().to_vec())
        };
        let with = format!(
            r#"{{"alg":"ECDH-ES","enc":"A128GCM","apu":"{}","apv":"{}","epk":{}}}"#,
            case.apu,
            case.apv,
            epk(&case.public_jwk)
        );
        let without = format!(
            r#"{{"alg":"ECDH-ES","enc":"A128GCM","apu":"{}","apv":"{}"}}"#,
            case.apu, case.apv
        );
        // the control: with the `epk` the RFC prints, the token opens under the content key it derives
        assert_eq!(open(&sealed_under(&with, &cek)), Ok(b"Hello".to_vec()));
        // without `epk` no content key can be derived: the token is Decrypt even though it is well formed
        // and sealed under an all-zero key, the one a decoder that supplied a default would reach
        assert_eq!(
            open(&sealed_under(&without, &[0; 16])),
            Err(jose::ErrorKind::Decrypt)
        );
        assert_eq!(
            open(&sealed_under(&without, &cek)),
            Err(jose::ErrorKind::Decrypt)
        );
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (3, 1));
}
