//! Unbuilt: Client extension inputs, outputs and their processing (R120 to R128; L3 10.1); lands with webauthn-14.
use alloc::string::String;
use alloc::vec::Vec;

use base::{Secret, SecretBytes};

use crate::record::CredentialId;

/// Unbuilt: lands with webauthn-14; no public function takes or returns it yet (CONTRACT, Planned).
///
/// A FIDO AppID (L3 10.1.1): an `https` URL, hashed as written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppId(pub(crate) String);

/// Unbuilt: lands with webauthn-14; no public function takes or returns it yet (CONTRACT, Planned).
///
/// PRF salts to evaluate (L3 10.1.4 `AuthenticationExtensionsPRFValues`); a salt past `MAX_PRF_SALT` is `TooLarge` from the `start_*` that sends it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrfEval {
    pub(crate) first: Vec<u8>,
    pub(crate) second: Option<Vec<u8>>,
}

/// Unbuilt: lands with webauthn-14; no public function takes or returns it yet (CONTRACT, Planned).
///
/// The `prf` input of a registration.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrfRequest {
    /// Ask only whether PRF is enabled.
    Enable,
    /// Ask for PRF and evaluate at creation.
    Eval(PrfEval),
}

/// Unbuilt: lands with webauthn-14; no public function takes or returns it yet (CONTRACT, Planned).
///
/// The `largeBlob` input of an authentication: one operation per ceremony.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LargeBlobOp {
    /// `read: true`.
    Read,
    /// `write`: a blob past `MAX_LARGE_BLOB` is `TooLarge` from `start_authentication`.
    Write(Vec<u8>),
}

/// Unbuilt: lands with webauthn-14; no public function takes or returns it yet (CONTRACT, Planned).
///
/// The `largeBlob` support input of a registration.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LargeBlobRequest {
    /// `required`.
    Required,
    /// `preferred`.
    Preferred,
}

/// Unbuilt: lands with webauthn-14; no public function takes or returns it yet (CONTRACT, Planned).
///
/// `credProps.rk`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Discoverability {
    /// Not requested.
    NotRequested,
    /// Requested, and the client gave no output (always, without the `serde` response shape).
    Unreported,
    /// `rk: true`.
    Discoverable,
    /// `rk: false`.
    NonDiscoverable,
}

/// Unbuilt: lands with webauthn-14; no public function takes or returns it yet (CONTRACT, Planned).
///
/// The `prf` client output.
#[non_exhaustive]
#[derive(Debug)]
pub enum PrfResult {
    /// Not requested.
    NotRequested,
    /// Requested, and the client gave no output (always, without the `serde` response shape).
    Unreported,
    /// `enabled: false`, or requested at authentication and nothing evaluated.
    NotEnabled,
    /// Enabled at registration, nothing evaluated.
    Enabled,
    /// Evaluated.
    Evaluated(PrfOutputs),
}

/// Unbuilt: lands with webauthn-14; no public function takes or returns it yet (CONTRACT, Planned).
///
/// PRF results: secrets, never printed or serialized.
#[derive(Debug)]
#[expect(dead_code, reason = "read by the accessors of webauthn-14")]
pub struct PrfOutputs {
    pub(crate) first: Secret<32>,
    pub(crate) second: Option<Secret<32>>,
}

/// Unbuilt: lands with webauthn-14; no public function takes or returns it yet (CONTRACT, Planned).
///
/// The `largeBlob` registration output.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LargeBlobSupport {
    /// Not requested.
    NotRequested,
    /// Requested, and the client gave no output (always, without the `serde` response shape).
    Unreported,
    /// `supported: true`.
    Supported,
    /// `supported: false`, under `LargeBlobRequest::Preferred`.
    Unsupported,
}

/// Unbuilt: lands with webauthn-14; no public function takes or returns it yet (CONTRACT, Planned).
///
/// The `largeBlob` authentication output.
#[non_exhaustive]
#[derive(Debug)]
pub enum LargeBlobOutcome {
    /// Not requested.
    NotRequested,
    /// Requested, and the client gave no output (always, without the `serde` response shape).
    Unreported,
    /// The blob read.
    Read(SecretBytes),
    /// `written: true`.
    Written,
    /// `written: false`, or no blob was found to read.
    NotDone,
}

/// Unbuilt: lands with webauthn-14; no public function takes or returns it yet (CONTRACT, Planned).
///
/// The `appid` client output.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppIdUsed {
    /// `appid: true`: `rpIdHash` was the AppID's.
    Used,
    /// Not requested, or `appid: false`.
    NotUsed,
}

/// The extension inputs a registration requested, held in its options and its ceremony row.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RegistrationExtensions {
    pub(crate) cred_props: bool,
    pub(crate) prf: Option<PrfRequest>,
    pub(crate) large_blob: Option<LargeBlobRequest>,
    pub(crate) app_id_exclude: Option<AppId>,
}

/// The extension inputs an authentication requested, held in its options and its ceremony row.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct AuthenticationExtensions {
    pub(crate) app_id: Option<AppId>,
    pub(crate) prf: Option<PrfEval>,
    pub(crate) prf_by_credential: Vec<(CredentialId, PrfEval)>,
    pub(crate) large_blob: Option<LargeBlobOp>,
}

/// `clientExtensionResults` as the client sent them; empty unless the `serde` response shape filled them in.
#[derive(Debug, Default)]
#[expect(dead_code, reason = "read by the extension processing of webauthn-14")]
pub(crate) struct ClientOutputs {
    pub(crate) app_id: Option<bool>,
    pub(crate) cred_props_rk: Option<bool>,
    pub(crate) prf_enabled: Option<bool>,
    pub(crate) prf_first: Option<SecretBytes>,
    pub(crate) prf_second: Option<SecretBytes>,
    pub(crate) large_blob_supported: Option<bool>,
    pub(crate) large_blob_blob: Option<SecretBytes>,
    pub(crate) large_blob_written: Option<bool>,
    /// Member names this crate does not read, each unsolicited (R128).
    pub(crate) unsolicited: Vec<String>,
}

/// The extension outputs of a registration.
#[derive(Debug)]
#[expect(dead_code, reason = "read by the accessors of webauthn-14")]
pub(crate) struct RegistrationOutputs {
    pub(crate) discoverability: Discoverability,
    pub(crate) prf: PrfResult,
    pub(crate) large_blob: LargeBlobSupport,
}

/// The extension outputs of an authentication.
#[derive(Debug)]
#[expect(dead_code, reason = "read by the accessors of webauthn-14")]
pub(crate) struct AuthenticationOutputs {
    pub(crate) app_id: AppIdUsed,
    pub(crate) prf: PrfResult,
    pub(crate) large_blob: LargeBlobOutcome,
}
