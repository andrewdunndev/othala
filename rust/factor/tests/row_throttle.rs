//! Row m3-factor-throttle, the claims reachable through the public API: R7's bounds, and R8 and R9 with no row.
use base::{Row, UnixTime, Version};
use factor::{Backoff, Cap, Closed, ErrorKind, FreeAttempts, Record, Throttle, Wait};

fn out_of_range<T>(r: Result<T, factor::Error>) -> bool {
    matches!(r, Err(e) if e.kind() == ErrorKind::OutOfRange)
}

#[test]
fn policy_bounds() {
    assert!(out_of_range(FreeAttempts::new(0)));
    assert!(FreeAttempts::new(1).is_ok() && FreeAttempts::new(10).is_ok());
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
        FreeAttempts::new(1)?,
        Wait::new(1)?,
        Cap::new(3_600)?,
    ));
    for now in [0, 1, u64::MAX].map(UnixTime::new) {
        assert!(strict.check(None, now).is_ok());
        assert!(Throttle::unlimited().check(None, now).is_ok());
    }
    Ok(())
}

#[test]
fn a_row_from_a_fast_clock_waits_at_most_one_cap() -> Result<(), Box<dyn std::error::Error>> {
    let t = Throttle::new(Backoff::new(
        FreeAttempts::new(2)?,
        Wait::new(60)?,
        Cap::new(3_600)?,
    ));
    let (now, ahead) = (1_000u64, 1_000 + 100 * 365 * 86_400u64);
    let mut bytes = vec![1, 0];
    bytes.extend_from_slice(&9u32.to_be_bytes());
    bytes.extend_from_slice(&ahead.to_be_bytes());
    let Record::Attempts(a) = Record::decode(&bytes)? else {
        return Err("not an attempts row".into());
    };
    let row = Row::new(&a, Version::new(7));
    let closed = Err(Closed::Wait(UnixTime::new(now + 3_600)));
    assert_eq!(t.check(Some(row), UnixTime::new(now)).map(drop), closed);
    Ok(())
}
