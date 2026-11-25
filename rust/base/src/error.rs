use core::fmt;

/// What went wrong; never carries secret-derived detail.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// Input is not canonical unpadded base64url.
    Malformed,
    /// A key appears twice in one effect, merge or lift.
    Overlap,
    /// An effect exceeds [`crate::MAX_EFFECT_SIZE`].
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
        todo!()
    }

    /// What went wrong.
    pub const fn kind(&self) -> ErrorKind {
        todo!()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for Error {}
