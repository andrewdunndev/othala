//! `authenticator_data`: the input as the authenticator data of an assertion response, with the control assertion's
//! client data.
use webauthn_rp::{AuthenticationResponse, ErrorKind};

const CLIENT_DATA: &[u8] = br#"{"type":"webauthn.get","challenge":"EijdmqrPNtPCSCR4aUB_y-czWE3Q7fYuiakE10n5Mdc","origin":"https://example.org","crossOrigin":false}"#;

pub(crate) fn check(data: &[u8]) -> Result<(), ErrorKind> {
    AuthenticationResponse::new(&[1; 16], CLIENT_DATA, data, &[], None)
        .map(drop)
        .map_err(|e| e.kind())
}
