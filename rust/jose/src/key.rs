//! Validated key material and its family, the leaf every algorithm and format builds on.
use base::SecretBytes;

use expose::Expose as _;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fam {
    Oct,
    P256,
    P384,
    P521,
    Ed25519,
    Rsa,
}

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

fn copy(key: &SecretBytes) -> SecretBytes {
    SecretBytes::new(key.expose().to_vec())
}

pub(crate) fn dup(key: &Public) -> Public {
    match key {
        Public::Oct(k) => Public::Oct(copy(k)),
        Public::P256(k) => Public::P256(*k),
        Public::P384(k) => Public::P384(*k),
        #[cfg(feature = "es512")]
        Public::P521(k) => Public::P521(*k),
        Public::Ed25519(k) => Public::Ed25519(*k),
        Public::Rsa(k) => Public::Rsa(k.clone()),
    }
}

pub(crate) fn dup_private(key: &Private) -> Private {
    match key {
        Private::Oct(k) => Private::Oct(copy(k)),
        Private::P256(k) => Private::P256(k.clone()),
        Private::P384(k) => Private::P384(k.clone()),
        #[cfg(feature = "es512")]
        Private::P521(k) => Private::P521(k.clone()),
        Private::Ed25519(k) => Private::Ed25519(k.clone()),
        Private::Rsa(k) => Private::Rsa(k.clone()),
    }
}

pub(crate) fn public_of(key: &Private) -> Public {
    match key {
        Private::Oct(k) => Public::Oct(copy(k)),
        Private::P256(k) => Public::P256(k.public_key()),
        Private::P384(k) => Public::P384(k.public_key()),
        #[cfg(feature = "es512")]
        Private::P521(k) => Public::P521(k.public_key()),
        Private::Ed25519(k) => Public::Ed25519(k.verifying_key()),
        Private::Rsa(k) => Public::Rsa(k.to_public_key()),
    }
}

/// The family of a public key, and its length when symmetric.
pub(crate) fn public_info(key: &Public) -> (Fam, usize) {
    match key {
        Public::Oct(k) => (Fam::Oct, k.expose().len()),
        Public::P256(_) => (Fam::P256, 0),
        Public::P384(_) => (Fam::P384, 0),
        #[cfg(feature = "es512")]
        Public::P521(_) => (Fam::P521, 0),
        Public::Ed25519(_) => (Fam::Ed25519, 0),
        Public::Rsa(_) => (Fam::Rsa, 0),
    }
}

pub(crate) fn private_info(key: &Private) -> (Fam, usize) {
    match key {
        Private::Oct(k) => (Fam::Oct, k.expose().len()),
        Private::P256(_) => (Fam::P256, 0),
        Private::P384(_) => (Fam::P384, 0),
        #[cfg(feature = "es512")]
        Private::P521(_) => (Fam::P521, 0),
        Private::Ed25519(_) => (Fam::Ed25519, 0),
        Private::Rsa(_) => (Fam::Rsa, 0),
    }
}
