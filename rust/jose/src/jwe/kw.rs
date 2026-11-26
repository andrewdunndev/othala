//! AES key wrap, AES-GCM key wrap and `dir` (RFC 7518 sections 4.4, 4.5 and 4.7).

/// AES-128 Key Wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A128Kw;

/// AES-192 Key Wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A192Kw;

/// AES-256 Key Wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A256Kw;

/// AES-128-GCM key wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A128GcmKw;

/// AES-192-GCM key wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A192GcmKw;

/// AES-256-GCM key wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A256GcmKw;

/// The shared symmetric key is the content-encryption key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Dir;
