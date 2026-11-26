//! RS256, RS384 and RS512 verification (RFC 7518 section 3.3).

/// RSASSA-PKCS1-v1_5 with SHA-256.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rs256;

/// RSASSA-PKCS1-v1_5 with SHA-384.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rs384;

/// RSASSA-PKCS1-v1_5 with SHA-512.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rs512;
