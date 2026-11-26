/// What went wrong; never carries key-, plaintext- or claim-derived detail.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// Not the grammar the RFC defines: segments, base64url, JSON, UTF-8, member types, curve points.
    Malformed,
    /// Input past one of the crate's named bounds.
    TooLarge,
    /// A JSON member named twice at any depth, or a header member in more than one of a token's headers.
    DuplicateMember,
    /// An algorithm, curve or compression value this crate does not implement, or one whose feature is off.
    UnsupportedAlg,
    /// The header's `alg` or `enc` is an implemented one other than the key's, or the key's type or curve cannot
    /// take the algorithm.
    AlgMismatch,
    /// A JWK without `alg` used where the algorithm must come from the key.
    KeyAlgMissing,
    /// A `crit` header member, which names no extension this crate understands.
    CriticalHeader,
    /// An RSA modulus below [`crate::MIN_RSA_BITS`], or a symmetric key shorter than its algorithm requires.
    WeakKey,
    /// A key whose `use` or `key_ops` does not permit the operation.
    KeyUse,
    /// No signature verified under the key.
    BadSignature,
    /// Decryption failed; one value for every cause, so no failure is an oracle.
    Decrypt,
    /// `exp` is at or before `now` minus the leeway.
    Expired,
    /// `nbf` or `iat` is after `now` plus the leeway.
    NotYetValid,
    /// `iss` is not the policy's issuer.
    Issuer,
    /// `aud` does not contain the policy's audience.
    Audience,
    /// `typ` is not the token kind's.
    Type,
    /// A claim the policy requires is absent.
    MissingClaim,
    /// A registered claim is present with the wrong JSON type.
    ClaimType,
    /// A [`crate::Signer`] could not sign (an HSM or KMS failure).
    Signer,
}

/// The crate's one error type: an [`ErrorKind`] and nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
}
