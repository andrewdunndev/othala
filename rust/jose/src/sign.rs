//! Issuing: the protected header, the signing input handed to a signer, and the compact token.
use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::key::Private;
use crate::{Alg, Kid, SignAlg};

/// The protected header of a JWS this crate issues: `alg` is `A`'s, so it is never `none`; `kid` when given, and
/// `typ` when issued as a JWT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header<A: Alg> {
    pub(crate) kid: Option<Kid>,
    pub(crate) typ: Option<&'static str>,
    pub(crate) alg: PhantomData<A>,
}

/// A JWS awaiting its `A` signature: the signing input goes to a signer (WebCrypto, a KMS, a [`crate::Signer`]),
/// and the signature comes back. This is the one effect the crate hands a host. `Debug` prints the header only.
#[must_use]
pub struct Unsigned<A: Alg> {
    pub(crate) header: Header<A>,
    pub(crate) input: Vec<u8>,
}

/// A compact JWS or JWE this crate produced. A bearer value: no `Display`, no equality, `Debug` prints its length
/// only.
#[derive(Clone)]
pub struct Compact(pub(crate) String);

/// A private or symmetric key that signs `A`. Not `Clone`, not `Serialize`, `Debug` redacted.
pub struct SigningKey<A: SignAlg> {
    pub(crate) material: Private,
    pub(crate) alg: PhantomData<A>,
}
