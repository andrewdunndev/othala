//! COSE keys and algorithms (R5; L3 5.8.5, 6.5.1); ES256 with webauthn-02, the other algorithms with webauthn-08.

/// A COSE algorithm this crate verifies.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CoseAlgorithm {
    /// -7, ECDSA P-256 with SHA-256.
    Es256,
    /// -35, ECDSA P-384 with SHA-384.
    Es384,
    /// -8, Ed25519.
    EdDsa,
    /// -257, RSASSA-PKCS1-v1_5 with SHA-256.
    Rs256,
}

/// A credential public key, checked against its algorithm's curve or modulus bounds when parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(dead_code, reason = "built by the COSE parser of webauthn-02")]
pub(crate) enum CoseKey {
    /// EC2 P-256, uncompressed coordinates.
    Es256 { x: [u8; 32], y: [u8; 32] },
    /// EC2 P-384, uncompressed coordinates.
    Es384 { x: [u8; 48], y: [u8; 48] },
    /// OKP Ed25519 point.
    EdDsa([u8; 32]),
    /// RSA modulus and exponent, big-endian.
    Rs256 {
        n: alloc::vec::Vec<u8>,
        e: alloc::vec::Vec<u8>,
    },
}
