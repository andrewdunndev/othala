//! ES256 and ES384 (RFC 7518 section 3.4), `R || S` only.
use p256::ecdsa::signature::{Signer, Verifier};

use crate::alg::sealed;
use crate::key::{Private, Public};
use crate::{Alg, Error, ErrorKind, LocalAlg, PublicAlg, SignAlg, SigningAlg};

/// ECDSA on P-256 with SHA-256.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Es256;

/// ECDSA on P-384 with SHA-384.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Es384;

macro_rules! es {
    ($marker:ident, $variant:ident, $curve:ident, $alg:ident, $len:literal) => {
        impl Alg for $marker {
            const ALG: SigningAlg = SigningAlg::$alg;
            type Signature = [u8; $len];
        }

        impl PublicAlg for $marker {}

        impl SignAlg for $marker {}

        impl LocalAlg for $marker {}

        #[expect(
            private_interfaces,
            reason = "sealed: the trait is unnameable outside the crate"
        )]
        impl sealed::Alg for $marker {
            fn verify(key: &Public, input: &[u8], signature: &[u8]) -> Result<(), Error> {
                let Public::$variant(key) = key else {
                    return Err(ErrorKind::AlgMismatch.into());
                };
                let signature = $curve::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| ErrorKind::BadSignature)?;
                $curve::ecdsa::VerifyingKey::from(key)
                    .verify(input, &signature)
                    .map_err(|_| ErrorKind::BadSignature.into())
            }
        }

        #[expect(
            private_interfaces,
            reason = "sealed: the trait is unnameable outside the crate"
        )]
        impl sealed::Local for $marker {
            fn sign(key: &Private, input: &[u8]) -> Result<[u8; $len], Error> {
                let Private::$variant(key) = key else {
                    return Err(ErrorKind::AlgMismatch.into());
                };
                let signature: $curve::ecdsa::Signature = $curve::ecdsa::SigningKey::from(key)
                    .try_sign(input)
                    .map_err(|_| ErrorKind::Signer)?;
                Ok(signature.to_bytes().into())
            }
        }
    };
}

es!(Es256, P256, p256, Es256, 64);
es!(Es384, P384, p384, Es384, 96);

#[cfg(test)]
mod tests {
    use super::{Es256, Es384};
    use crate::alg::sealed::{Alg as _, Local as _};
    use crate::key::{Private, Public};
    use crate::{Alg, ErrorKind};

    #[test]
    fn signatures_verify_only_under_their_curve() {
        let (p256, p384) = (
            p256::SecretKey::from_slice(&[1; 32]).ok(),
            p384::SecretKey::from_slice(&[1; 48]).ok(),
        );
        let (public256, public384) = (
            p256.as_ref().map(|k| Public::P256(k.public_key())),
            p384.as_ref().map(|k| Public::P384(k.public_key())),
        );
        let (private256, private384) = (p256.map(Private::P256), p384.map(Private::P384));
        let sig256 = private256
            .as_ref()
            .and_then(|k| Es256::sign(k, b"input").ok());
        let sig384 = private384
            .as_ref()
            .and_then(|k| Es384::sign(k, b"input").ok());
        assert_eq!(sig256.as_ref().map(|s| s.len()), Some(64));
        assert_eq!(sig384.as_ref().map(|s| s.len()), Some(96));
        let sig256 = sig256.unwrap_or([0; 64]);
        let sig384 = sig384.unwrap_or([0; 96]);
        let check = |key: &Option<Public>, alg256: bool, input: &[u8]| {
            let key = key.as_ref();
            let result = if alg256 {
                key.map(|k| Es256::verify(k, input, &sig256))
            } else {
                key.map(|k| Es384::verify(k, input, &sig384))
            };
            result.map(|r| r.err().map(|e| e.kind()))
        };
        assert_eq!(check(&public256, true, b"input"), Some(None));
        assert_eq!(check(&public384, false, b"input"), Some(None));
        assert_eq!(
            check(&public256, true, b"other"),
            Some(Some(ErrorKind::BadSignature))
        );
        assert_eq!(
            check(&public384, true, b"input"),
            Some(Some(ErrorKind::AlgMismatch))
        );
        assert_eq!(
            check(&public256, false, b"input"),
            Some(Some(ErrorKind::AlgMismatch))
        );
        let signed = private384
            .as_ref()
            .and_then(|k| Es256::sign(k, b"input").err());
        assert_eq!(signed.map(|e| e.kind()), Some(ErrorKind::AlgMismatch));
        let signed = private256
            .as_ref()
            .and_then(|k| Es384::sign(k, b"input").err());
        assert_eq!(signed.map(|e| e.kind()), Some(ErrorKind::AlgMismatch));
        assert_eq!((Es256::ALG.name(), Es384::ALG.name()), ("ES256", "ES384"));
    }
}
