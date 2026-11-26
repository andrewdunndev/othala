//! JWT claims under a policy (RFC 7519 section 4.1, RFC 8725 sections 3.8 to 3.12).
use alloc::string::String;
use core::marker::PhantomData;

/// A kind of JWT: its `typ` and its claims. One per kind, so a policy never crosses kinds.
pub trait TokenKind {
    /// The `typ` this kind carries and requires.
    const TYP: Typ;
    /// The claims this kind yields, read strictly from the payload.
    type Claims: serde::de::DeserializeOwned;
}

/// A kind its own issuer may read back without being an audience, as an OP reads its `id_token_hint`
/// (OpenID Connect RP-Initiated Logout 1.0 section 2). Opt-in: only such a kind has `Policy::read_back`, and
/// only that policy takes [`Expiry::Unchecked`].
pub trait ReadBack: TokenKind {}

/// The `typ` header rule of a [`TokenKind`] (RFC 8725 sections 3.11 and 3.12).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Typ {
    /// Exactly this media type, compared case-insensitively with any `application/` prefix removed, e.g. `at+jwt`.
    Explicit(&'static str),
    /// `JWT` or absent: a kind that predates explicit typing, kept apart by its issuer, audience and claims.
    Generic,
}

/// The `exp` rule of a [`Policy`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expiry {
    /// `exp` must be present, numeric and after `now` minus the leeway; every `Policy::new` policy.
    Required,
    /// `exp`, when present, must be numeric; its time is not compared. Only `Policy::read_back` takes it.
    Unchecked,
}

/// What a JWT of kind `K` must satisfy before its claims are read. No `Default`; `Clone`, `Debug` and equality ask
/// nothing of `K`.
pub struct Policy<K: TokenKind> {
    pub(crate) issuer: Issuer,
    pub(crate) audience: Option<Audience>,
    pub(crate) leeway: Leeway,
    pub(crate) expiry: Expiry,
    pub(crate) kind: PhantomData<fn() -> K>,
}

/// An expected `iss`, compared byte for byte. A consumer's own URL rule wraps this type's constructor.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Issuer(pub(crate) String);

/// An expected `aud` entry, compared byte for byte.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Audience(pub(crate) String);

/// Clock leeway in seconds, at most [`crate::MAX_LEEWAY`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Leeway(pub(crate) u64);
