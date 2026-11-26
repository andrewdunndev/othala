//! Parsed responses: shape checked before a finish runs, nothing verified (R16, R17, R20); bodies with webauthn-04 and webauthn-05.
/// A parsed `AuthenticatorAttestationResponse`: client data, CBOR, authenticator data and statement shape checked, nothing verified. `Debug` prints no input bytes.
#[derive(Clone)]
pub struct RegistrationResponse(());

/// A parsed `AuthenticatorAssertionResponse`. `Debug` prints no input bytes.
#[derive(Clone)]
pub struct AuthenticationResponse(());

/// The keys an authentication response names.
#[derive(Clone, Debug)]
pub struct Lookup(());
