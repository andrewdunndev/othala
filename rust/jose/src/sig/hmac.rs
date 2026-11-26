//! HS256, HS384 and HS512 (RFC 7518 section 3.2).

/// HMAC with SHA-256.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hs256;

/// HMAC with SHA-384.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hs384;

/// HMAC with SHA-512.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hs512;
