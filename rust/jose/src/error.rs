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
    pub(crate) kind: ErrorKind,
}

impl Error {
    /// What went wrong.
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self { kind }
    }
}

impl ErrorKind {
    /// A fixed sentence naming the caller's next action; it holds no key, plaintext or claim bytes.
    const fn message(self) -> &'static str {
        match self {
            Self::Malformed => "input is not well-formed; reject it, it cannot be repaired",
            Self::TooLarge => {
                "input exceeds a size bound; reject it, or raise the bound if the input is trusted"
            }
            Self::DuplicateMember => "a member appears twice; reject the input, it is ambiguous",
            Self::UnsupportedAlg => {
                "algorithm, curve or compression is not supported; choose an implemented one or enable its feature"
            }
            Self::AlgMismatch => {
                "algorithm does not match the key; use a key of the type and curve the algorithm takes"
            }
            Self::KeyAlgMissing => {
                "key has no alg; set the algorithm on the key or pass it explicitly"
            }
            Self::CriticalHeader => {
                "token requires a critical header extension this crate does not understand; reject the token"
            }
            Self::WeakKey => "key is below the algorithm's minimum size; use a larger key",
            Self::KeyUse => {
                "key does not permit this operation; use a key whose use and key_ops allow it"
            }
            Self::BadSignature => {
                "no signature verified; reject the token, or check that the verification key is the issuer's"
            }
            Self::Decrypt => "decryption failed; reject the token, no cause is given",
            Self::Expired => "token has expired; obtain a fresh token",
            Self::NotYetValid => {
                "token is not valid yet; retry later or check the clocks and leeway"
            }
            Self::Issuer => {
                "issuer is not the expected one; reject the token or check the policy's issuer"
            }
            Self::Audience => {
                "audience does not include this recipient; reject the token or check the policy's audience"
            }
            Self::Type => {
                "token type is not the expected one; reject the token or check the policy's type"
            }
            Self::MissingClaim => {
                "a required claim is absent; reject the token or check the policy's required claims"
            }
            Self::ClaimType => "a registered claim has the wrong JSON type; reject the token",
            Self::Signer => "the signer failed; check the HSM or KMS and retry",
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.kind.message())
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;
    use alloc::string::ToString;

    use crate::{Error, ErrorKind};

    /// Every kind with its position and exact text; the match has no `_` arm, so a new kind fails to compile here.
    fn row(kind: ErrorKind) -> (usize, &'static str) {
        match kind {
            ErrorKind::Malformed => (
                0,
                "input is not well-formed; reject it, it cannot be repaired",
            ),
            ErrorKind::TooLarge => (
                1,
                "input exceeds a size bound; reject it, or raise the bound if the input is trusted",
            ),
            ErrorKind::DuplicateMember => (
                2,
                "a member appears twice; reject the input, it is ambiguous",
            ),
            ErrorKind::UnsupportedAlg => (
                3,
                "algorithm, curve or compression is not supported; choose an implemented one or enable its feature",
            ),
            ErrorKind::AlgMismatch => (
                4,
                "algorithm does not match the key; use a key of the type and curve the algorithm takes",
            ),
            ErrorKind::KeyAlgMissing => (
                5,
                "key has no alg; set the algorithm on the key or pass it explicitly",
            ),
            ErrorKind::CriticalHeader => (
                6,
                "token requires a critical header extension this crate does not understand; reject the token",
            ),
            ErrorKind::WeakKey => (
                7,
                "key is below the algorithm's minimum size; use a larger key",
            ),
            ErrorKind::KeyUse => (
                8,
                "key does not permit this operation; use a key whose use and key_ops allow it",
            ),
            ErrorKind::BadSignature => (
                9,
                "no signature verified; reject the token, or check that the verification key is the issuer's",
            ),
            ErrorKind::Decrypt => (10, "decryption failed; reject the token, no cause is given"),
            ErrorKind::Expired => (11, "token has expired; obtain a fresh token"),
            ErrorKind::NotYetValid => (
                12,
                "token is not valid yet; retry later or check the clocks and leeway",
            ),
            ErrorKind::Issuer => (
                13,
                "issuer is not the expected one; reject the token or check the policy's issuer",
            ),
            ErrorKind::Audience => (
                14,
                "audience does not include this recipient; reject the token or check the policy's audience",
            ),
            ErrorKind::Type => (
                15,
                "token type is not the expected one; reject the token or check the policy's type",
            ),
            ErrorKind::MissingClaim => (
                16,
                "a required claim is absent; reject the token or check the policy's required claims",
            ),
            ErrorKind::ClaimType => (
                17,
                "a registered claim has the wrong JSON type; reject the token",
            ),
            ErrorKind::Signer => (18, "the signer failed; check the HSM or KMS and retry"),
        }
    }

    const ALL: [ErrorKind; 19] = [
        ErrorKind::Malformed,
        ErrorKind::TooLarge,
        ErrorKind::DuplicateMember,
        ErrorKind::UnsupportedAlg,
        ErrorKind::AlgMismatch,
        ErrorKind::KeyAlgMissing,
        ErrorKind::CriticalHeader,
        ErrorKind::WeakKey,
        ErrorKind::KeyUse,
        ErrorKind::BadSignature,
        ErrorKind::Decrypt,
        ErrorKind::Expired,
        ErrorKind::NotYetValid,
        ErrorKind::Issuer,
        ErrorKind::Audience,
        ErrorKind::Type,
        ErrorKind::MissingClaim,
        ErrorKind::ClaimType,
        ErrorKind::Signer,
    ];

    #[test]
    fn each_kind_reads_distinctly() {
        for (at, kind) in ALL.into_iter().enumerate() {
            let (index, text) = row(kind);
            assert_eq!(index, at, "{kind:?} is out of order in ALL");
            let error = Error::from(kind);
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), text);
            // fixed prose: no quoting, bracketing or digits that could carry input or a Debug form
            assert!(
                text.chars()
                    .all(|c| c.is_ascii_alphabetic() || " ;,'_-".contains(c)),
                "{kind:?}: {text}"
            );
            assert!(!text.contains(&alloc::format!("{kind:?}")));
        }
        let texts: BTreeSet<_> = ALL.iter().map(|&k| Error::from(k).to_string()).collect();
        assert_eq!(texts.len(), ALL.len());
    }
}
