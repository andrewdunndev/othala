//! ES256 and ES384 (RFC 7518 section 3.4), `R || S` only.

/// ECDSA on P-256 with SHA-256.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Es256;

/// ECDSA on P-384 with SHA-384.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Es384;
