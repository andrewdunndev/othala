#![expect(
    dead_code,
    reason = "fields are read by the bodies factor-05 and factor-07 land"
)]

use alloc::string::String;

use zeroize::Zeroizing;

/// A password as presented at login: 1 byte to 4,096 bytes, wiped on drop.
pub struct Password(Zeroizing<String>);

/// Which NIST SP 800-63B-4 minimum a new password meets.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Minimum {
    /// 15 code points: the password alone authenticates.
    SingleFactor,
    /// 8 code points: the password is only ever one factor of several.
    MultiFactor,
}

/// A password a subject chose, held to its length rule; only these are hashed.
pub struct NewPassword(Password);

/// Argon2id memory in KiB.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Memory(u32);

/// Argon2id passes over memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Passes(u32);

/// Argon2id lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Lanes(u32);

/// An Argon2id cost at or above an OWASP minimum configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cost {
    memory: Memory,
    passes: Passes,
    lanes: Lanes,
}

/// An Argon2id v19 hash in canonical PHC string form, held to this crate's policy; the host stores it.
#[derive(Clone)]
pub struct Phc(String);

/// Whether a matched hash is below the cost the verifier was given.
#[non_exhaustive]
#[derive(Clone)]
pub enum Rehash {
    /// The stored hash meets the cost.
    Current,
    /// The presented password hashed again at the cost, for the host to store in place of the old hash.
    Needed(Phc),
}

/// A presented password matched the stored hash.
pub struct PasswordMatch {
    rehash: Rehash,
}
