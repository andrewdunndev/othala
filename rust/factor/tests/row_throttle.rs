//! Row m3-factor-throttle, the claims reachable through the public API: R7's bounds, and R8 and R9 with no row.
use base::UnixTime;
use factor::{Backoff, Cap, ErrorKind, FreeAttempts, Throttle, Wait};

fn out_of_range<T>(r: Result<T, factor::Error>) -> bool {
    matches!(r, Err(e) if e.kind() == ErrorKind::OutOfRange)
}

#[test]
fn policy_bounds() {
    assert!(FreeAttempts::new(0).is_ok() && FreeAttempts::new(10).is_ok());
    assert!(out_of_range(FreeAttempts::new(11)));
    assert!(out_of_range(Wait::new(0)));
    assert!(Wait::new(1).is_ok() && Wait::new(3_600).is_ok());
    assert!(out_of_range(Wait::new(3_601)));
    assert!(out_of_range(Cap::new(3_599)));
    assert!(Cap::new(3_600).is_ok() && Cap::new(86_400).is_ok());
    assert!(out_of_range(Cap::new(86_401)));
}

#[test]
fn no_row_permits() -> Result<(), factor::Error> {
    let strict = Throttle::new(Backoff::new(
        FreeAttempts::new(0)?,
        Wait::new(1)?,
        Cap::new(3_600)?,
    ));
    for now in [0, 1, u64::MAX].map(UnixTime::new) {
        assert!(strict.check(None, now).is_ok());
        assert!(Throttle::unlimited().check(None, now).is_ok());
    }
    Ok(())
}
