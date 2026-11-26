//! EdDSA over Ed25519 (RFC 8037 section 3.1), verified with `verify_strict`.

/// EdDSA over Ed25519; Ed448 is not implemented.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EdDsa;
