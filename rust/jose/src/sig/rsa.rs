//! RS256, RS384 and RS512 verification (RFC 7518 section 3.3).
use rsa::Pkcs1v15Sign;
use sha2::{Digest as _, Sha256, Sha384, Sha512};

use crate::alg::sealed;
use crate::key::Public;
use crate::{Alg, Error, ErrorKind, PublicAlg, SigningAlg};

/// RSASSA-PKCS1-v1_5 with SHA-256.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rs256;

/// RSASSA-PKCS1-v1_5 with SHA-384.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rs384;

/// RSASSA-PKCS1-v1_5 with SHA-512.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rs512;

macro_rules! rs {
    ($marker:ident, $hash:ty, $alg:ident) => {
        impl Alg for $marker {
            const ALG: SigningAlg = SigningAlg::$alg;
            type Signature = alloc::vec::Vec<u8>;
        }

        impl PublicAlg for $marker {}

        #[expect(
            private_interfaces,
            reason = "sealed: the trait is unnameable outside the crate"
        )]
        impl sealed::Alg for $marker {
            fn verify(key: &Public, input: &[u8], signature: &[u8]) -> Result<(), Error> {
                let Public::Rsa(key) = key else {
                    return Err(ErrorKind::AlgMismatch.into());
                };
                key.verify(
                    Pkcs1v15Sign::new::<$hash>(),
                    &<$hash>::digest(input),
                    signature,
                )
                .map_err(|_| ErrorKind::BadSignature.into())
            }
        }
    };
}

rs!(Rs256, Sha256, Rs256);
rs!(Rs384, Sha384, Rs384);
rs!(Rs512, Sha512, Rs512);

#[cfg(test)]
mod tests {
    use super::{Rs256, Rs384, Rs512};
    use crate::alg::sealed::Alg as _;
    use crate::key::Public;
    use crate::{Alg, ErrorKind};

    #[test]
    fn only_an_rsa_key_serves() {
        let key = p256::SecretKey::from_slice(&[1; 32])
            .ok()
            .map(|k| Public::P256(k.public_key()));
        let kinds = key.map(|k| {
            [
                Rs256::verify(&k, b"", b""),
                Rs384::verify(&k, b"", b""),
                Rs512::verify(&k, b"", b""),
            ]
            .map(|r| r.err().map(|e| e.kind()))
        });
        assert_eq!(kinds, Some([Some(ErrorKind::AlgMismatch); 3]));
        assert_eq!(
            [Rs256::ALG.name(), Rs384::ALG.name(), Rs512::ALG.name()],
            ["RS256", "RS384", "RS512"]
        );
    }
}
