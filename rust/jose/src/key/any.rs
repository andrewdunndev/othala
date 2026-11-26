use crate::SigningAlg;
use crate::key::{Private, Public};

/// A verification key bound at runtime to one algorithm, for JWK Set consumers. Not `Clone`, `Debug` redacted.
pub struct AnyVerifyKey {
    pub(crate) alg: SigningAlg,
    pub(crate) material: Public,
}

/// A signing key bound at runtime to its JWK's `alg`, for a host that signs by `kid`: HS, ES and EdDSA.
/// Not `Clone`, not `Serialize`, `Debug` redacted.
pub struct AnySigningKey {
    pub(crate) alg: SigningAlg,
    pub(crate) material: Private,
}
