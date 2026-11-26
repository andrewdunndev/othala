//! AES-GCM and AES-CBC with HMAC-SHA-2 content encryption (RFC 7518 sections 5.2 and 5.3).

/// AES-128-GCM.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A128Gcm;

/// AES-192-GCM.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A192Gcm;

/// AES-256-GCM.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A256Gcm;

/// AES-128-CBC with HMAC SHA-256, the tag truncated to 128 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A128CbcHs256;

/// AES-192-CBC with HMAC SHA-384, the tag truncated to 192 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A192CbcHs384;

/// AES-256-CBC with HMAC SHA-512, the tag truncated to 256 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A256CbcHs512;
