/// Seconds since the Unix epoch; every call that needs time takes one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTime(u64);

impl UnixTime {
    /// The instant `secs` seconds after the epoch.
    pub const fn new(secs: u64) -> Self {
        Self(secs)
    }

    /// Seconds since the epoch.
    pub const fn secs(self) -> u64 {
        self.0
    }
}

#[cfg(feature = "std")]
impl From<std::time::SystemTime> for UnixTime {
    /// Instants before the epoch saturate to the epoch.
    fn from(t: std::time::SystemTime) -> Self {
        Self(
            t.duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::UnixTime;

    #[test]
    fn seconds_round_trip() {
        assert_eq!(UnixTime::new(42).secs(), 42);
    }

    #[cfg(feature = "std")]
    #[test]
    fn system_time_saturates_before_epoch() {
        use std::time::{Duration, UNIX_EPOCH};
        assert_eq!(
            UnixTime::from(UNIX_EPOCH + Duration::from_secs(5)),
            UnixTime::new(5)
        );
        assert_eq!(
            UnixTime::from(UNIX_EPOCH - Duration::from_secs(5)),
            UnixTime::new(0)
        );
    }
}
