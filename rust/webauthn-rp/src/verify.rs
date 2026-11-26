//! The ceremonies: start, finish and their verdicts (L3 7.1, 7.2); authentication with webauthn-04, registration with webauthn-05.

use crate::extensions::{AuthenticationOutputs, RegistrationOutputs};
use crate::options::UserHandle;
use crate::record::{Credential, CredentialId};

/// A verified registration; made only by `finish_registration`.
#[derive(Debug)]
#[expect(dead_code, reason = "read by its accessors, webauthn-05")]
pub struct Registered {
    pub(crate) credential: Credential,
    pub(crate) user_verification: UserVerification,
    pub(crate) extensions: RegistrationOutputs,
}

/// A verified assertion; made only by `finish_authentication`.
#[derive(Debug)]
#[expect(dead_code, reason = "read by its accessors, webauthn-04")]
pub struct Assertion {
    pub(crate) credential_id: CredentialId,
    pub(crate) user: UserHandle,
    pub(crate) user_verification: AssertionVerification,
    pub(crate) backup: Backup,
    pub(crate) counter: Counter,
    pub(crate) extensions: AuthenticationOutputs,
}

/// The UV flag of a registration, and a credential's `uvInitialized`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserVerification {
    /// UV set.
    Verified,
    /// UP only.
    PresenceOnly,
}

/// The UV flag of an assertion, read against the credential's `uvInitialized` (L3 6.1 and 7.2 step 24).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssertionVerification {
    /// UV set, and `uvInitialized` true: an authentication factor.
    Verified,
    /// UV set, and `uvInitialized` false: not a factor until an extra one succeeds and `confirm_user_verification` commits.
    FirstUse,
    /// UV clear.
    PresenceOnly,
}

/// The BE and BS flags; BS without BE has no value here.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backup {
    /// BE clear: a single-device credential.
    SingleDevice,
    /// BE set: a multi-device credential, with BS.
    MultiDevice(BackupState),
}

/// The BS flag of a multi-device credential.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupState {
    /// BS set.
    BackedUp,
    /// BS clear.
    NotBackedUp,
}

/// What the signature counter did (L3 7.2 step 22).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Counter {
    /// Stored and seen are both zero.
    Unsupported,
    /// Seen is greater than stored.
    Advanced(u32),
    /// Seen is not greater than stored, under `CounterPolicy::Tolerate`.
    Regressed {
        /// The stored count, which the effect keeps.
        stored: u32,
        /// The count in the assertion.
        seen: u32,
    },
}
