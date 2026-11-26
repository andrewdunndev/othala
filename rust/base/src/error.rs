use core::fmt;

/// What went wrong; never carries secret-derived detail.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// Input is not canonical unpadded base64url, or not the length expected.
    Malformed,
    /// A key appears twice in one effect, merge or lift.
    Overlap,
    /// An effect exceeds [`crate::MAX_EFFECT_SIZE`], or text exceeds [`crate::MAX_B64URL_TEXT`].
    TooLarge,
    /// An effect has no guard.
    Empty,
    /// A lift changes a key's [`crate::Scope`].
    ScopeChanged,
    /// An effect's keys map to more than one transaction domain.
    SpansDomains,
    /// A receipt was minted for another effect.
    WrongReceipt,
}

/// The crate's one error type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    pub(crate) const fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }

    /// What went wrong.
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.kind {
            ErrorKind::Malformed => "malformed base64url",
            ErrorKind::Overlap => "key named twice in one effect",
            ErrorKind::TooLarge => "input or effect exceeds its bound",
            ErrorKind::Empty => "effect has no guard",
            ErrorKind::ScopeChanged => "lift changes a key's scope",
            ErrorKind::SpansDomains => "effect spans transaction domains",
            ErrorKind::WrongReceipt => "receipt is for another effect",
        })
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::{Error, ErrorKind};
    use alloc::collections::BTreeSet;
    use alloc::string::ToString;

    #[test]
    fn each_kind_reads_distinctly() {
        let kinds = [
            ErrorKind::Malformed,
            ErrorKind::Overlap,
            ErrorKind::TooLarge,
            ErrorKind::Empty,
            ErrorKind::ScopeChanged,
            ErrorKind::SpansDomains,
            ErrorKind::WrongReceipt,
        ];
        let texts: BTreeSet<_> = kinds.iter().map(|&k| Error::new(k).to_string()).collect();
        assert_eq!(texts.len(), kinds.len());
        assert!(!texts.contains(""));
        assert!(kinds.iter().all(|&k| Error::new(k).kind() == k));
    }

    #[test]
    fn too_large_names_text_and_effects() {
        let e = crate::b64url_decode(&"A".repeat(crate::MAX_B64URL_TEXT + 1))
            .map_err(|e| e.to_string());
        assert_eq!(e, Err("input or effect exceeds its bound".into()));
    }
}
