//! EdDSA over Ed25519 (RFC 8037 section 3).
use ed25519_dalek::{Signature, Signer as _};

use crate::alg::sealed;
use crate::key::{Private, Public};
use crate::{Alg, Error, ErrorKind, LocalAlg, PublicAlg, SignAlg, SigningAlg};

/// EdDSA on Ed25519.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EdDsa;

impl Alg for EdDsa {
    const ALG: SigningAlg = SigningAlg::EdDsa;
    type Signature = [u8; 64];
}

impl PublicAlg for EdDsa {}

impl SignAlg for EdDsa {}

impl LocalAlg for EdDsa {}

#[expect(
    private_interfaces,
    reason = "sealed: the trait is unnameable outside the crate"
)]
impl sealed::Alg for EdDsa {
    fn verify(key: &Public, input: &[u8], signature: &[u8]) -> Result<(), Error> {
        let Public::Ed25519(key) = key else {
            return Err(ErrorKind::AlgMismatch.into());
        };
        let signature = Signature::from_slice(signature).map_err(|_| ErrorKind::BadSignature)?;
        key.verify_strict(input, &signature)
            .map_err(|_| ErrorKind::BadSignature.into())
    }
}

#[expect(
    private_interfaces,
    reason = "sealed: the trait is unnameable outside the crate"
)]
impl sealed::Local for EdDsa {
    fn sign(key: &Private, input: &[u8]) -> Result<[u8; 64], Error> {
        let Private::Ed25519(key) = key else {
            return Err(ErrorKind::AlgMismatch.into());
        };
        Ok(key.sign(input).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::EdDsa;
    use crate::alg::sealed::{Alg as _, Local as _};
    use crate::key::{Private, Public};
    use crate::{Alg, ErrorKind};

    #[test]
    fn signatures_verify_only_under_their_key() {
        let secret = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let public = Public::Ed25519(secret.verifying_key());
        let signature = EdDsa::sign(&Private::Ed25519(secret), b"input").unwrap_or([0; 64]);
        assert_eq!(
            EdDsa::verify(&public, b"input", &signature)
                .err()
                .map(|e| e.kind()),
            None
        );
        assert_eq!(
            EdDsa::verify(&public, b"other", &signature)
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::BadSignature)
        );
        let other = p256::SecretKey::from_slice(&[1; 32]).ok();
        let verified = other
            .as_ref()
            .map(|k| EdDsa::verify(&Public::P256(k.public_key()), b"", &[0; 64]));
        assert_eq!(
            verified.and_then(|r| r.err()).map(|e| e.kind()),
            Some(ErrorKind::AlgMismatch)
        );
        let signed = other.map(|k| EdDsa::sign(&Private::P256(k), b""));
        assert_eq!(
            signed.and_then(|r| r.err()).map(|e| e.kind()),
            Some(ErrorKind::AlgMismatch)
        );
        assert_eq!(EdDsa::ALG.name(), "EdDSA");
    }
}
