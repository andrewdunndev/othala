//! PS256, PS384 and PS512 verification (RFC 7518 section 3.5), salt the hash length.

/// RSASSA-PSS with SHA-256 and MGF1 with SHA-256.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ps256;

/// RSASSA-PSS with SHA-384 and MGF1 with SHA-384.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ps384;

/// RSASSA-PSS with SHA-512 and MGF1 with SHA-512.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ps512;
