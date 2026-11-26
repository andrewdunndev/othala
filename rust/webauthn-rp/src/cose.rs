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
