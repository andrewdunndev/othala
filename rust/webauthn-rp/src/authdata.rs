//! Authenticator data and attested credential data (R4); lands with webauthn-04.
use alloc::vec::Vec;

use crate::cose::CoseKey;
use crate::record::{Aaguid, CredentialId};

/// Parsed authenticator data (L3 6.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthData {
    /// `rpIdHash`.
    pub(crate) rp_id_hash: [u8; 32],
    /// The flags byte: UP 0x01, UV 0x04, BE 0x08, BS 0x10, AT 0x40, ED 0x80.
    pub(crate) flags: u8,
    /// `signCount`.
    pub(crate) sign_count: u32,
    /// Attested credential data, present exactly when AT is set.
    pub(crate) attested: Option<AttestedCredential>,
    /// The extensions map's CBOR bytes, present exactly when ED is set.
    pub(crate) extensions: Option<Vec<u8>>,
}

/// Attested credential data (L3 6.5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AttestedCredential {
    /// The AAGUID, as the authenticator reported it.
    pub(crate) aaguid: Aaguid,
    /// The credential id.
    pub(crate) id: CredentialId,
    /// The credential public key, parsed.
    pub(crate) public_key: CoseKey,
    /// The credential public key's CBOR bytes, which tpm, android-key and apple compare with their certified key.
    pub(crate) public_key_cbor: Vec<u8>,
}
