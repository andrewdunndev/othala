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
