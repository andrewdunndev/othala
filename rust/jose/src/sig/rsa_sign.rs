//! RS and PS signing through the blinded private-key path (feature `rsa-sign`).
use alloc::vec::Vec;

use base::Entropy;
use rsa::{Pkcs1v15Sign, Pss};
use sha2::{Digest as _, Sha256, Sha384, Sha512};

use crate::alg::sealed;
use crate::key::Private;
use crate::rng::Source;
use crate::{BlindedAlg, Error, ErrorKind, Ps256, Ps384, Ps512, Rs256, Rs384, Rs512, SignAlg};

macro_rules! blinded {
    ($marker:ident, $hash:ty, $scheme:expr) => {
        impl SignAlg for $marker {}

        impl BlindedAlg for $marker {}

        #[expect(
            private_interfaces,
            reason = "sealed: the trait is unnameable outside the crate"
        )]
        impl sealed::Blinded for $marker {
            fn sign(key: &Private, input: &[u8], e: &mut dyn Entropy) -> Result<Vec<u8>, Error> {
                let Private::Rsa(key) = key else {
                    return Err(ErrorKind::AlgMismatch.into());
                };
                key.sign_with_rng(&mut Source(e), $scheme, &<$hash>::digest(input))
                    .map_err(|_| ErrorKind::Signer.into())
            }
        }
    };
}

blinded!(Rs256, Sha256, Pkcs1v15Sign::new::<Sha256>());
blinded!(Rs384, Sha384, Pkcs1v15Sign::new::<Sha384>());
blinded!(Rs512, Sha512, Pkcs1v15Sign::new::<Sha512>());
blinded!(Ps256, Sha256, Pss::<Sha256>::new());
blinded!(Ps384, Sha384, Pss::<Sha384>::new());
blinded!(Ps512, Sha512, Pss::<Sha512>::new());
