#![expect(dead_code, reason = "fields are read by the bodies factor-03 lands")]

use base::{UnixTime, Version};

/// The subject's attempt count since the last reset, and when the last one was made; stored under [`crate::Key::Attempts`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attempts {
    count: u32,
    last: UnixTime,
}

/// How many attempts after a reset wait for nothing: 0 to 10.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FreeAttempts(u32);

/// The wait before the first attempt past the free ones, in seconds: 1 to 3,600.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wait(u64);

/// The longest wait the doubling reaches, in seconds: a policy value from 3,600 (1 hour) to 86,400 (1 day).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cap(u64);

/// The throttle policy: free attempts, then a wait that doubles per attempt up to the cap; never a lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backoff {
    free: FreeAttempts,
    first: Wait,
    cap: Cap,
}

/// Issues the one [`Permit`] each verification needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Throttle {
    policy: Option<Backoff>,
}

/// Why no permit was issued.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Closed {
    /// The next attempt is permitted at or after this time.
    Wait(UnixTime),
}

/// Leave to verify once, against the attempt count it was issued from, at the time it was issued.
#[derive(Debug)]
pub struct Permit {
    seen: Option<(Version, Attempts)>,
    at: UnixTime,
}
