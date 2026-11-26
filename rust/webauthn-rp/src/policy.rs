//! Relying-party identity and fixed policy: RP ID, origins, cross-origin, counter and trust policies (R8, R9, R19); bodies with webauthn-03.
use alloc::string::String;
use alloc::vec::Vec;

use crate::options::DisplayName;

/// A relying party identifier: a lowercase ASCII domain of at most `MAX_RP_ID` bytes, validated.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RpId(pub(crate) String);

/// A serialized web origin (`https://host[:port]`, or `http://localhost[:port]`) or an `android:apk-key-hash:` origin, compared exactly.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Origin(pub(crate) String);

/// What a signature counter that did not advance means.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CounterPolicy {
    /// The assertion fails with `CounterRegressed`.
    Reject,
    /// The assertion succeeds and reports `Counter::Regressed`.
    Tolerate,
}

/// Whether a ceremony may run in a cross-origin iframe (L3 7.1 steps 10-11, 7.2 steps 13-14).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrossOrigin {
    /// `crossOrigin: true` and any `topOrigin` fail.
    Deny,
    /// Cross-origin is allowed under any top origin, or none reported.
    AnyTop,
    /// Cross-origin is allowed only with a reported `topOrigin` in this list.
    Listed(Vec<Origin>),
}

/// What an extension output the ceremony did not request means.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnsolicitedExtensions {
    /// The ceremony fails with `Extension`.
    Reject,
    /// The output is ignored.
    Ignore,
}

/// Whether a registration needs attestation that chains to a trust anchor (L3 7.1 step 24).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustPolicy {
    /// None, self and unanchored attestation fail with `Untrusted`.
    RequireTrusted,
    /// Every verified attestation registers; `Registered` reports how far it was trusted.
    AcceptUntrusted,
}

/// Which android-key authorization lists may carry origin and purpose (L3 8.4.1).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyEnforcement {
    /// Only `teeEnforced`.
    TrustedEnvironment,
    /// The union of `teeEnforced` and `softwareEnforced`.
    AnyList,
}

/// One relying party's fixed policy: RP ID, origins and every ceremony option that is not per call.
#[derive(Clone)]
#[expect(
    dead_code,
    reason = "read by the ceremonies of webauthn-03 to webauthn-05"
)]
pub struct RelyingParty {
    pub(crate) id: RpId,
    pub(crate) name: DisplayName,
    pub(crate) origins: Vec<Origin>,
    pub(crate) counter: CounterPolicy,
    pub(crate) cross_origin: CrossOrigin,
    pub(crate) unsolicited: UnsolicitedExtensions,
    pub(crate) trust: TrustPolicy,
    pub(crate) android_key: KeyEnforcement,
}

/// Builds a [`RelyingParty`]; cross-origin, unsolicited extensions and untrusted Android lists are off unless set, and unanchored attestation registers unless `TrustPolicy::RequireTrusted` is set.
#[must_use]
#[derive(Clone)]
#[expect(dead_code, reason = "read by build, webauthn-03")]
pub struct RelyingPartyBuilder(pub(crate) RelyingParty);
