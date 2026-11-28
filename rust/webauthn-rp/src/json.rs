//! Unbuilt: JSON shapes (5.1.8-9), related origins (5.11) and signals (5.1.10), serialized under `serde` (R130 to R135); lands with webauthn-15.
use alloc::vec::Vec;

use crate::options::{UserEntity, UserHandle};
use crate::policy::{Origin, RpId};
use crate::record::CredentialId;

/// Unbuilt: lands with webauthn-15; no public function takes or returns it yet (CONTRACT, Planned).
///
/// What a client signal method reports (L3 5.1.10).
#[non_exhaustive]
#[derive(Clone)]
pub enum Signal {
    /// `signalUnknownCredential`: the RP has no such credential.
    UnknownCredential(CredentialId),
    /// `signalAllAcceptedCredentials`: the user's full current list.
    AllAcceptedCredentials(UserHandle, Vec<CredentialId>),
    /// `signalCurrentUserDetails`: the user's current names.
    CurrentUserDetails(UserEntity),
}

/// Unbuilt: lands with webauthn-15; no public function takes or returns it yet (CONTRACT, Planned).
///
/// The options object for a signal method, with the RP ID filled in; serialized under `serde`.
#[derive(Clone)]
#[expect(dead_code, reason = "read by the serializer of webauthn-15")]
pub struct SignalOptions {
    pub(crate) rp_id: RpId,
    pub(crate) signal: Signal,
}

/// Unbuilt: lands with webauthn-15; no public function takes or returns it yet (CONTRACT, Planned).
///
/// The `/.well-known/webauthn` document: `{"origins": [...]}`; serialized under `serde`.
#[derive(Clone, Debug)]
#[expect(dead_code, reason = "read by the serializer of webauthn-15")]
pub struct RelatedOrigins(pub(crate) Vec<Origin>);
