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
    /// The header's `alg` or `enc` is any value other than the key's (a refused one such as `none` included), or the
    /// key's type or curve cannot take the algorithm.
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

/// Lists every kind once more with its fixed text, and from that list builds `ALL` and the text lookup. A kind
/// missing here fails to compile (the match below is exhaustive), and so does a name that is not a kind.
macro_rules! kind_texts {
    ($($name:ident => $text:literal,)*) => {
        impl ErrorKind {
            /// Every kind, for the table test.
            #[cfg(test)]
            const ALL: &'static [Self] = &[$(Self::$name),*];

            /// A fixed sentence naming the caller's next action; it holds no key, plaintext or claim bytes.
            const fn message(self) -> &'static str {
                match self {
                    $(Self::$name => $text,)*
                }
            }
        }
    };
}

kind_texts! {
    Malformed => "input is not well-formed; reject it, it cannot be repaired",
    TooLarge => "input exceeds a size bound; reject it, or raise the bound if the input is trusted",
    DuplicateMember => "a member appears twice; reject the input, it is ambiguous",
    UnsupportedAlg => "algorithm, curve or compression is not supported; choose an implemented one or enable its feature",
    AlgMismatch => "algorithm does not match the key; use a key of the type and curve the algorithm takes",
    KeyAlgMissing => "key has no alg; set the algorithm on the key or pass it explicitly",
    CriticalHeader => "token requires a critical header extension this crate does not understand; reject the token",
    WeakKey => "key is below the algorithm's minimum size; use a larger key",
    KeyUse => "key does not permit this operation; use a key whose use and key_ops allow it",
    BadSignature => "no signature verified; reject the token, or check that the verification key is the issuer's",
    Decrypt => "decryption failed; reject the token, no cause is given",
    Expired => "token has expired; obtain a fresh token",
    NotYetValid => "token is not valid yet; retry later or check the clocks and leeway",
    Issuer => "issuer is not the expected one; reject the token or check the policy's issuer",
    Audience => "audience does not include this recipient; reject the token or check the policy's audience",
    Type => "token type is not the expected one; reject the token or check the policy's type",
    MissingClaim => "a required claim is absent; reject the token or check the policy's required claims",
    ClaimType => "a registered claim has the wrong JSON type; reject the token",
    Signer => "the signer failed; check the HSM or KMS and retry",
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

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.kind.message())
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use alloc::collections::{BTreeMap, BTreeSet};
    use alloc::format;
    use alloc::string::ToString;

    use crate::{Error, ErrorKind};

    #[test]
    fn each_kind_reads_distinctly() {
        let golden: BTreeMap<&str, &str> = include_str!("../tests/golden/error_texts.txt")
            .lines()
            .filter_map(|line| line.split_once('\t'))
            .collect();
        assert_eq!(golden.len(), ErrorKind::ALL.len());
        for &kind in ErrorKind::ALL {
            let error = Error::from(kind);
            assert_eq!(error.kind(), kind);
            let text = golden
                .get(format!("{kind:?}").as_str())
                .copied()
                .unwrap_or_default();
            assert_eq!(error.to_string(), text, "{kind:?}");
            // fixed prose: no quoting, bracketing or digits that could carry input or a Debug form
            assert!(
                text.chars()
                    .all(|c| c.is_ascii_alphabetic() || " ;,'_-".contains(c)),
                "{kind:?}: {text}"
            );
            assert!(!text.contains(&alloc::format!("{kind:?}")));
        }
        let texts: BTreeSet<_> = ErrorKind::ALL
            .iter()
            .map(|&k| Error::from(k).to_string())
            .collect();
        assert_eq!(texts.len(), ErrorKind::ALL.len());
    }
}
