//! JWK decoding (RFC 7517, RFC 7518 section 6, RFC 8037 section 2) and the key-type-to-algorithm binding.
use alloc::string::String;

use crate::key::{Private, Public};

/// A key id: an opaque lookup hint, compared byte for byte, never trusted.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Kid(pub(crate) String);

/// A JWK's key type (RFC 7518 section 6.1, RFC 8037 section 2).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kty {
    /// `EC`: P-256, P-384, or P-521 under `es512`.
    Ec,
    /// `RSA`.
    Rsa,
    /// `OKP`: Ed25519.
    Okp,
    /// `oct`: a symmetric key, only ever a [`SecretJwk`].
    Oct,
}

/// The members of a JWK beside its key material.
pub(crate) struct Meta {
    pub(crate) kid: Option<Kid>,
    pub(crate) alg: Option<&'static str>,
    pub(crate) usage: Usage,
}

/// The operations `use` and `key_ops` permit, one bit each; absent members permit every one the key type allows.
pub(crate) struct Usage(pub(crate) u8);

/// A public JWK (RFC 7517, RFC 7518 section 6, RFC 8037 section 2): EC on P-256, P-384 or P-521, RSA, or OKP
/// Ed25519, never private or symmetric material. Opaque: members are read through accessors and written by
/// `Serialize`.
pub struct Jwk {
    pub(crate) meta: Meta,
    pub(crate) material: Public,
}

/// A JWK holding private or symmetric key material, opaque. Not `Clone`, not `Serialize`, `Debug` redacted.
pub struct SecretJwk {
    pub(crate) meta: Meta,
    pub(crate) material: Private,
}
