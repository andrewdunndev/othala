//! PS256, PS384 and PS512 verification (RFC 7518 section 3.5), salt the hash length.
use rsa::Pss;
use sha2::{Digest as _, Sha256, Sha384, Sha512};

use crate::alg::sealed;
use crate::key::Public;
use crate::{Alg, Error, ErrorKind, PublicAlg, SigningAlg};

/// RSASSA-PSS with SHA-256 and MGF1 with SHA-256.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ps256;

/// RSASSA-PSS with SHA-384 and MGF1 with SHA-384.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ps384;

/// RSASSA-PSS with SHA-512 and MGF1 with SHA-512.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ps512;

macro_rules! ps {
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
                key.verify(Pss::<$hash>::new(), &<$hash>::digest(input), signature)
                    .map_err(|_| ErrorKind::BadSignature.into())
            }
        }
    };
}

ps!(Ps256, Sha256, Ps256);
ps!(Ps384, Sha384, Ps384);
ps!(Ps512, Sha512, Ps512);

#[cfg(test)]
mod tests {
    use super::{Ps256, Ps384, Ps512};
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
                Ps256::verify(&k, b"", b""),
                Ps384::verify(&k, b"", b""),
                Ps512::verify(&k, b"", b""),
            ]
            .map(|r| r.err().map(|e| e.kind()))
        });
        assert_eq!(kinds, Some([Some(ErrorKind::AlgMismatch); 3]));
        assert_eq!(
            [Ps256::ALG.name(), Ps384::ALG.name(), Ps512::ALG.name()],
            ["PS256", "PS384", "PS512"]
        );
    }
}
