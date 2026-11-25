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

    /// `secs` later, saturating at `u64::MAX` seconds.
    pub const fn saturating_add(self, secs: u64) -> Self {
        Self(self.0.saturating_add(secs))
    }

    /// `secs` earlier, saturating at the epoch.
    pub const fn saturating_sub(self, secs: u64) -> Self {
        Self(self.0.saturating_sub(secs))
    }

    /// Seconds from `earlier` to `self`, or `None` if `earlier` is later.
    pub const fn checked_duration_since(self, earlier: Self) -> Option<u64> {
        self.0.checked_sub(earlier.0)
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

    #[test]
    fn arithmetic_saturates() {
        let t = UnixTime::new;
        assert_eq!(t(5).saturating_add(3), t(8));
        assert_eq!(t(u64::MAX - 1).saturating_add(5), t(u64::MAX));
        assert_eq!(t(5).saturating_sub(3), t(2));
        assert_eq!(t(3).saturating_sub(5), t(0));
        assert_eq!(t(8).checked_duration_since(t(5)), Some(3));
        assert_eq!(t(5).checked_duration_since(t(5)), Some(0));
        assert_eq!(t(5).checked_duration_since(t(8)), None);
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
