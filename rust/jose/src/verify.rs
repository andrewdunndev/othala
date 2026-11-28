//! The verifying half of a bound key: a public or symmetric key that checks `A` signatures.
use core::marker::PhantomData;

use crate::key::Public;
use crate::{Alg, Error};

/// A key that verifies `A` signatures and nothing else. Not `Clone` (an HMAC key is a secret), `Debug` redacted.
pub struct VerifyKey<A: Alg> {
    pub(crate) material: Public,
    pub(crate) alg: PhantomData<A>,
}

impl<A: Alg> VerifyKey<A> {
    /// `Ok` when `signature` is `A`'s over `signing_input` under this key; any other outcome is `BadSignature`, and the
    /// comparison of an HMAC tag is constant time.
    pub fn verify_signature(&self, signing_input: &[u8], signature: &[u8]) -> Result<(), Error> {
        A::verify(&self.material, signing_input, signature)
    }
}

impl<A: Alg> core::fmt::Debug for VerifyKey<A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifyKey").field("alg", &A::ALG).finish()
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use base::SecretBytes;

    use crate::{Hs256, SecretJwk};

    #[test]
    fn debug_redacted() {
        let key =
            SecretJwk::from_oct(SecretBytes::new(alloc::vec![0x41; 32])).verify_key::<Hs256>();
        assert_eq!(format!("{:?}", key.ok()), "Some(VerifyKey { alg: Hs256 })");
    }
}
