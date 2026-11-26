//! Second factors and secret policy as sans-IO verdicts: Argon2id passwords under a PHC policy, TOTP, look-up
//! recovery codes, and one attempt throttle. Every verdict comes back inside a [`Pending`] whose effect counts the
//! attempt; the throttle's reset, merged into the consumer's session effect, is the one way the count falls.
#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod otp;
mod password;
mod recovery;
mod store;
mod throttle;

use core::fmt;

pub use otp::{Digits, OtpAlg, OtpCode, OtpKey, OtpMatch, Period, Skew, Totp, TotpStep};
pub use password::{
    Cost, Lanes, Memory, Minimum, NewPassword, Passes, Password, PasswordMatch, Phc, Rehash,
    password_hash, password_verify,
};
pub use recovery::{RecoveryCode, RecoveryCount, RecoveryHash, RecoveryMatch};
pub use store::{Effect, Key, Pending, Record, Rejected};
pub use throttle::{Attempts, Backoff, Cap, Closed, FreeAttempts, Permit, Throttle, Wait};

/// What went wrong; never carries secret-derived detail.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// Text or bytes are not in the stated form.
    Malformed,
    /// Input exceeds the parser's stated bound.
    TooLarge,
    /// A PHC string names another algorithm, version or parameter set.
    Unsupported,
    /// An Argon2id cost below every OWASP minimum configuration.
    WeakCost,
    /// An OTP key shorter than 128 bits.
    WeakKey,
    /// A new password shorter than its NIST minimum, or an empty presented one.
    PasswordLength,
    /// A policy or parameter value outside its stated range.
    OutOfRange,
    /// The host could not allocate an accepted cost's memory; it does not depend on the password.
    OutOfMemory,
    /// An effect the crate built failed base's bound; no accepted input reaches it.
    Internal,
}

/// The crate's one error type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    /// What went wrong.
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.kind {
            ErrorKind::Malformed => "input is not in its stated form",
            ErrorKind::TooLarge => "input exceeds its bound",
            ErrorKind::Unsupported => "unsupported password hash",
            ErrorKind::WeakCost => "password hash cost below the floor",
            ErrorKind::WeakKey => "OTP key too short",
            ErrorKind::PasswordLength => "password length outside its bounds",
            ErrorKind::OutOfRange => "parameter out of range",
            ErrorKind::OutOfMemory => "password hash memory unavailable",
            ErrorKind::Internal => "effect exceeds its bound",
        })
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec::Vec;

    use super::{Error, ErrorKind};

    pub(crate) fn unhex(text: &str) -> Option<Vec<u8>> {
        text.as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok())
            .collect()
    }

    #[test]
    fn display_names_the_kind_only() {
        let shown = |kind| Error { kind }.to_string();
        assert_eq!(
            shown(ErrorKind::Malformed),
            "input is not in its stated form"
        );
        assert_eq!(shown(ErrorKind::TooLarge), "input exceeds its bound");
        assert_eq!(shown(ErrorKind::Unsupported), "unsupported password hash");
        assert_eq!(
            shown(ErrorKind::WeakCost),
            "password hash cost below the floor"
        );
        assert_eq!(shown(ErrorKind::WeakKey), "OTP key too short");
        assert_eq!(
            shown(ErrorKind::PasswordLength),
            "password length outside its bounds"
        );
        assert_eq!(shown(ErrorKind::OutOfRange), "parameter out of range");
        assert_eq!(
            shown(ErrorKind::OutOfMemory),
            "password hash memory unavailable"
        );
        assert_eq!(shown(ErrorKind::Internal), "effect exceeds its bound");
        assert_eq!(
            Error {
                kind: ErrorKind::WeakKey
            }
            .kind(),
            ErrorKind::WeakKey
        );
    }
}
