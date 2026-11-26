//! ES512 (RFC 7518 section 3.4), feature `es512`.

/// ECDSA on P-521 with SHA-512 (feature `es512`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Es512;
