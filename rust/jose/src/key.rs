use core::marker::PhantomData;

use base::SecretBytes;

use crate::{Alg, Error};

pub(crate) mod any;

/// Validated public or symmetric key material: what a JWK, a verify key or an encryption key holds.
pub(crate) enum Public {
    Oct(SecretBytes),
    P256(p256::PublicKey),
    P384(p384::PublicKey),
    #[cfg(feature = "es512")]
    P521(p521::PublicKey),
    Ed25519(ed25519_dalek::VerifyingKey),
    Rsa(rsa::PublicKey),
}

/// Validated private or symmetric key material: what a secret JWK, a signing key or a decryption key holds.
pub(crate) enum Private {
    Oct(SecretBytes),
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    #[cfg(feature = "es512")]
    P521(p521::SecretKey),
    Ed25519(ed25519_dalek::SigningKey),
    Rsa(rsa::PrivateKey),
}

/// A key that verifies `A` signatures and nothing else. Not `Clone` (an HMAC key is a secret), `Debug` redacted.
pub struct VerifyKey<A: Alg> {
    pub(crate) material: Public,
    pub(crate) alg: PhantomData<A>,
}

/// A source of `A` signatures over a signing input: a [`crate::SigningKey`], an [`crate::AnySigningKey`], or a
/// host's HSM or KMS. Open on purpose; a device failure is the implementer's `Error` of kind `Signer`.
pub trait Signer<A: Alg> {
    /// The JWS signature over `input` in the RFC 7518 encoding (ECDSA as `R || S`).
    fn sign(&self, input: &[u8]) -> Result<A::Signature, Error>;
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
