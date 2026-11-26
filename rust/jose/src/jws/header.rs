//! The JOSE header a JWS carries (RFC 7515 section 4): the duplicate pre-scan, `crit`, and the `alg` comparison.
use alloc::string::String;

use crate::Kid;

/// One signature's protected and unprotected headers, merged after the duplicate check.
pub(crate) struct Parsed {
    pub(crate) alg: Option<String>,
    pub(crate) kid: Option<Kid>,
    pub(crate) typ: Option<String>,
    pub(crate) cty: Option<String>,
}
