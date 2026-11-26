//! Parsed responses: shape checked before a finish runs, nothing verified (R16, R17, R20); bodies with webauthn-04 and webauthn-05.
use alloc::vec::Vec;

use crate::authdata::AuthData;
use crate::client_data::ClientData;
use crate::extensions::ClientOutputs;
use crate::options::{Transport, UserHandle};
use crate::record::{CredentialId, Key};

/// A parsed `AuthenticatorAttestationResponse`: client data, CBOR, authenticator data and statement shape checked, nothing verified. `Debug` prints no input bytes.
#[expect(dead_code, reason = "read by finish_registration, webauthn-05")]
pub struct RegistrationResponse {
    pub(crate) client_data_json: Vec<u8>,
    pub(crate) client_data: ClientData,
    pub(crate) attestation_object: Vec<u8>,
    pub(crate) auth_data: AuthData,
    pub(crate) transports: Vec<Transport>,
    pub(crate) extensions: ClientOutputs,
}

/// A parsed `AuthenticatorAssertionResponse`. `Debug` prints no input bytes.
#[expect(dead_code, reason = "read by finish_authentication, webauthn-04")]
pub struct AuthenticationResponse {
    pub(crate) raw_id: CredentialId,
    pub(crate) client_data_json: Vec<u8>,
    pub(crate) client_data: ClientData,
    pub(crate) authenticator_data: Vec<u8>,
    pub(crate) auth_data: AuthData,
    pub(crate) signature: Vec<u8>,
    pub(crate) user_handle: Option<UserHandle>,
    pub(crate) extensions: ClientOutputs,
}

/// The keys an authentication response names.
#[derive(Clone, Debug)]
#[expect(dead_code, reason = "read by its accessors, webauthn-04")]
pub struct Lookup {
    pub(crate) ceremony: Key,
    pub(crate) credential: Key,
    pub(crate) user: Option<UserHandle>,
}
