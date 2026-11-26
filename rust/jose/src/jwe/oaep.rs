//! RSA-OAEP and RSA-OAEP-256 (RFC 7518 section 4.3), feature `rsa-decrypt`: one decryption path, a random CEK on OAEP failure.

/// RSAES-OAEP with SHA-1 and MGF1 with SHA-1 (feature `rsa-decrypt`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RsaOaep;

/// RSAES-OAEP with SHA-256 and MGF1 with SHA-256 (feature `rsa-decrypt`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RsaOaep256;
