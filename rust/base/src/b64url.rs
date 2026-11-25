use alloc::string::String;
use alloc::vec::Vec;

use crate::Error;

/// Unpadded base64url (RFC 4648 section 5).
pub fn b64url_encode(bytes: &[u8]) -> String {
    todo!()
}

/// Strict unpadded base64url: padding, a symbol outside the alphabet, or a non-canonical tail is `Malformed`.
pub fn b64url_decode(text: &str) -> Result<Vec<u8>, Error> {
    todo!()
}
