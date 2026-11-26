//! The JWS compact serialization (RFC 7515 section 7.1) and verification.
use alloc::vec::Vec;

use crate::Kid;
use crate::jws::header::Parsed;

/// One signature of a JWS: the protected header text as received, the merged header, the signature bytes.
pub(crate) struct Signature<'a> {
    pub(crate) protected: &'a str,
    pub(crate) header: Parsed,
    pub(crate) bytes: Vec<u8>,
}

/// A parsed JWS, not verified: no accessor reaches its payload, and `Debug` prints only the `kid`s.
pub struct Jws<'a> {
    pub(crate) payload: &'a str,
    pub(crate) signatures: Vec<Signature<'a>>,
    pub(crate) kids: Vec<Kid>,
}

/// A verified JWS payload: the signature holds, the content is not validated. `Debug` prints its length only.
pub struct Payload(pub(crate) Vec<u8>);
