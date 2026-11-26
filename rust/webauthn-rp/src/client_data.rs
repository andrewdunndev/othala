//! The bounded clientDataJSON reader (R6, R7); lands with webauthn-03.
use alloc::string::String;
use alloc::vec::Vec;

/// The members of `clientDataJSON` the ceremonies check; the steps compare them, the reader only reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClientData {
    /// `type`, as sent.
    pub(crate) kind: String,
    /// `challenge` decoded; empty when it is not canonical base64url, so no ceremony matches (R7).
    pub(crate) challenge: Vec<u8>,
    /// `origin`, as sent.
    pub(crate) origin: String,
    /// `crossOrigin`, when present.
    pub(crate) cross_origin: Option<bool>,
    /// `topOrigin`, when present.
    pub(crate) top_origin: Option<String>,
}
