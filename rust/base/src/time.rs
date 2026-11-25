/// Seconds since the Unix epoch; every call that needs time takes one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTime(u64);

impl UnixTime {
    /// The instant `secs` seconds after the epoch.
    pub const fn new(secs: u64) -> Self {
        todo!()
    }

    /// Seconds since the epoch.
    pub const fn secs(self) -> u64 {
        todo!()
    }
}

#[cfg(feature = "std")]
impl From<std::time::SystemTime> for UnixTime {
    /// Instants before the epoch saturate to the epoch.
    fn from(t: std::time::SystemTime) -> Self {
        todo!()
    }
}
