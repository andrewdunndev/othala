//! JWTs (RFC 7519 section 7.2): a compact JWS whose claims come out only through a policy.
use alloc::string::String;
use alloc::vec::Vec;

use crate::{Jws, Kid};

/// A parsed JWT, not verified; `Debug` prints only the `kid`.
pub struct Jwt<'a> {
    pub(crate) jws: Jws<'a>,
}

/// A JWT whose signature verified; its claims are reachable only through a [`crate::Policy`]. `Debug` prints its
/// `kid` only.
pub struct VerifiedJwt {
    pub(crate) kid: Option<Kid>,
    pub(crate) typ: Option<String>,
    pub(crate) cty: Option<String>,
    pub(crate) payload: Vec<u8>,
}
