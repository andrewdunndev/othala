//! ES512 (RFC 7518 section 3.4), feature `es512`.
use p521::ecdsa::signature::{Signer, Verifier};
use p521::ecdsa::{Signature, SigningKey, VerifyingKey};

use crate::alg::sealed;
use crate::key::{Private, Public};
use crate::{Alg, Error, ErrorKind, LocalAlg, PublicAlg, SignAlg, SigningAlg};

/// ECDSA on P-521 with SHA-512 (feature `es512`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Es512;

impl Alg for Es512 {
    const ALG: SigningAlg = SigningAlg::Es512;
    type Signature = [u8; 132];
}

impl PublicAlg for Es512 {}

impl SignAlg for Es512 {}

impl LocalAlg for Es512 {}

#[expect(
    private_interfaces,
    reason = "sealed: the trait is unnameable outside the crate"
)]
impl sealed::Alg for Es512 {
    fn verify(key: &Public, input: &[u8], signature: &[u8]) -> Result<(), Error> {
        let Public::P521(key) = key else {
            return Err(ErrorKind::AlgMismatch.into());
        };
        let signature = Signature::from_slice(signature).map_err(|_| ErrorKind::BadSignature)?;
        VerifyingKey::from(key)
            .verify(input, &signature)
            .map_err(|_| ErrorKind::BadSignature.into())
    }
}

#[expect(
    private_interfaces,
    reason = "sealed: the trait is unnameable outside the crate"
)]
impl sealed::Local for Es512 {
    fn sign(key: &Private, input: &[u8]) -> Result<[u8; 132], Error> {
        let Private::P521(key) = key else {
            return Err(ErrorKind::AlgMismatch.into());
        };
        let signature: Signature = SigningKey::from(key)
            .try_sign(input)
            .map_err(|_| ErrorKind::Signer)?;
        Ok(signature.to_bytes().into())
    }
}

#[cfg(test)]
mod tests {
    use super::Es512;
    use crate::alg::sealed::{Alg as _, Local as _};
    use crate::key::{Private, Public};
    use crate::{Alg, ErrorKind};

    #[test]
    fn signatures_verify_only_under_their_key() {
        let secret = p521::SecretKey::from_slice(&[1; 66]).ok();
        let public = secret.as_ref().map(|k| Public::P521(k.public_key()));
        let private = secret.map(Private::P521);
        let signature = private.as_ref().and_then(|k| Es512::sign(k, b"input").ok());
        assert_eq!(signature.map(|s| s.len()), Some(132));
        let signature = signature.unwrap_or([0; 132]);
        let check = |input: &[u8]| {
            public
                .as_ref()
                .map(|k| Es512::verify(k, input, &signature).err().map(|e| e.kind()))
        };
        assert_eq!(check(b"input"), Some(None));
        assert_eq!(check(b"other"), Some(Some(ErrorKind::BadSignature)));
        let other = p256::SecretKey::from_slice(&[1; 32]).ok();
        let verified = other
            .as_ref()
            .map(|k| Es512::verify(&Public::P256(k.public_key()), b"", &[0; 132]));
        assert_eq!(
            verified.and_then(|r| r.err()).map(|e| e.kind()),
            Some(ErrorKind::AlgMismatch)
        );
        let signed = other.map(|k| Es512::sign(&Private::P256(k), b""));
        assert_eq!(
            signed.and_then(|r| r.err()).map(|e| e.kind()),
            Some(ErrorKind::AlgMismatch)
        );
        assert_eq!(Es512::ALG.name(), "ES512");
    }
}
