//! JWK Set decoding, lookup and publication (RFC 7517 section 5).
use alloc::vec::Vec;

use crate::{Jwk, SecretJwk};

/// A JWK Set: the public keys, and any private or symmetric ones a decoded document held, in document order.
/// `Serialize` writes the public keys only.
pub struct JwkSet {
    pub(crate) keys: Vec<Member>,
}

/// One kept key of a set.
pub(crate) enum Member {
    Public(Jwk),
    Secret(SecretJwk),
}

/// The key a `kid` names in a [`JwkSet`].
#[non_exhaustive]
#[derive(Clone, Copy)]
pub enum JwkEntry<'a> {
    /// A public key.
    Public(&'a Jwk),
    /// A private or symmetric key.
    Secret(&'a SecretJwk),
}
