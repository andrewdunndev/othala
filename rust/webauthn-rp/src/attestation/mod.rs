//! Attestation statement formats, each compiled only under its own feature (R100); dispatch and `none` (R90) with webauthn-05.
#[cfg(feature = "android-key")]
mod android_key;

#[cfg(feature = "apple")]
mod apple;

#[cfg(any(
    feature = "packed",
    feature = "tpm",
    feature = "android-key",
    feature = "apple",
    feature = "fido-u2f"
))]
mod chain;

#[cfg(feature = "fido-u2f")]
mod fido_u2f;

#[cfg(feature = "packed")]
mod packed;

#[cfg(feature = "tpm")]
mod tpm;

use alloc::vec::Vec;

use crate::authdata::AuthData;
use crate::cbor::Value;
use crate::trust::AttestationType;

/// What every format's verification reads (L3 8, the verification procedure's inputs).
#[expect(dead_code, reason = "built by the format dispatch of webauthn-05")]
pub(crate) struct Statement<'a> {
    /// `attStmt`.
    pub(crate) att_stmt: &'a Value<'a>,
    /// The authenticator data, parsed.
    pub(crate) auth_data: &'a AuthData,
    /// The authenticator data as signed.
    pub(crate) auth_data_bytes: &'a [u8],
    /// SHA-256 of `clientDataJSON`.
    pub(crate) client_data_hash: [u8; 32],
}

/// A format's verified result: its attestation type and trust path, leaf first (empty for none and self).
#[expect(
    dead_code,
    reason = "built by each format, read by the dispatch of webauthn-05"
)]
pub(crate) struct Verified {
    /// The attestation type.
    pub(crate) kind: AttestationType,
    /// The `x5c` certificates in DER, leaf first.
    pub(crate) x5c: Vec<Vec<u8>>,
}
