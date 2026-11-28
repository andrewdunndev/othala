//! `attestation_object`: the input as the attestation object of a registration response, with the control
//! registration's client data and its attested credential id as the raw id, so any other credential id reads
//! `CredentialIdInvalid`.
use webauthn_rp::{ErrorKind, RegistrationResponse};

const RAW_ID: [u8; 32] = [
    0x8d, 0x6d, 0x31, 0xee, 0xb5, 0xa2, 0x91, 0x64, 0x03, 0xca, 0xa1, 0x7d, 0xcc, 0x59, 0x64, 0x29,
    0xa4, 0x09, 0x2a, 0xea, 0xb4, 0x5d, 0x55, 0xfc, 0xcc, 0x35, 0xf5, 0xb8, 0x0e, 0x85, 0xf6, 0x17,
];
const CLIENT_DATA: &[u8] = br#"{"type":"webauthn.create","challenge":"EijdmqrPNtPCSCR4aUB_y-czWE3Q7fYuiakE10n5Mdc","origin":"https://example.org","crossOrigin":false}"#;

pub(crate) fn check(data: &[u8]) -> Result<(), ErrorKind> {
    RegistrationResponse::new(&RAW_ID, CLIENT_DATA, data, &[])
        .map(drop)
        .map_err(|e| e.kind())
}
