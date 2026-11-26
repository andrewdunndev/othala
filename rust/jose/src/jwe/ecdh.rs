//! ECDH-ES and ECDH-ES+A*KW on P-256, P-384 and (feature `es512`) P-521 (RFC 7518 section 4.6); no X25519.

/// ECDH-ES direct key agreement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EcdhEs;

/// ECDH-ES with AES-128 Key Wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EcdhEsA128Kw;

/// ECDH-ES with AES-192 Key Wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EcdhEsA192Kw;

/// ECDH-ES with AES-256 Key Wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EcdhEsA256Kw;
