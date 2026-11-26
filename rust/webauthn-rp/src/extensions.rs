//! Client extension inputs, outputs and their processing (R120 to R128; L3 10.1); lands with webauthn-14.
use alloc::vec::Vec;

use base::SecretBytes;

/// A FIDO AppID (L3 10.1.1): an `https` URL, hashed as written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppId(());

/// PRF salts to evaluate (L3 10.1.4 `AuthenticationExtensionsPRFValues`); a salt past `MAX_PRF_SALT` is `TooLarge` from the `start_*` that sends it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrfEval(());

/// The `prf` input of a registration.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrfRequest {
    /// Ask only whether PRF is enabled.
    Enable,
    /// Ask for PRF and evaluate at creation.
    Eval(PrfEval),
}

/// The `largeBlob` input of an authentication: one operation per ceremony.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LargeBlobOp {
    /// `read: true`.
    Read,
    /// `write`: a blob past `MAX_LARGE_BLOB` is `TooLarge` from `start_authentication`.
    Write(Vec<u8>),
}

/// The `largeBlob` support input of a registration.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LargeBlobRequest {
    /// `required`.
    Required,
    /// `preferred`.
    Preferred,
}

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

/// PRF results: secrets, never printed or serialized.
#[derive(Debug)]
pub struct PrfOutputs(());

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

/// The `appid` client output.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppIdUsed {
    /// `appid: true`: `rpIdHash` was the AppID's.
    Used,
    /// Not requested, or `appid: false`.
    NotUsed,
}
