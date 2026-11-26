#![expect(
    dead_code,
    reason = "fields are read by the bodies factor-02 and factor-06 land"
)]

use alloc::vec::Vec;

use zeroize::Zeroizing;

/// The HMAC hash of an authenticator.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OtpAlg {
    /// HMAC-SHA-1, the RFC 4226 and RFC 6238 default.
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

/// The number of decimal digits in a code.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Digits {
    /// Six digits.
    Six,
    /// Eight digits.
    Eight,
}

/// The TOTP time step: 15 to 300 seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Period(u32);

/// How many steps either side of the current one are accepted.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Skew {
    /// The current step only.
    Exact,
    /// One step before or after.
    One,
}

/// An authenticator's shared secret: 16 to 64 bytes, wiped on drop.
pub struct OtpKey(Zeroizing<Vec<u8>>);

/// An RFC 6238 authenticator with T0 at the epoch; the host stores it, and its last step is a row of its own.
pub struct Totp {
    key: OtpKey,
    alg: OtpAlg,
    digits: Digits,
    period: Period,
    skew: Skew,
}

/// The last step an authenticator accepted; stored under [`crate::Key::TotpStep`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TotpStep(u64);

/// A code as presented: six or eight ASCII digits, wiped on drop.
pub struct OtpCode {
    digits: Zeroizing<[u8; 8]>,
    len: Digits,
}

/// A code matched a step after the last one accepted.
#[derive(Debug)]
pub struct OtpMatch {
    step: TotpStep,
}
