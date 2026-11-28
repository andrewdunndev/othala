//! Row m3-factor-throttle, the claims reachable through the public API: R7's bounds, and R8 with no row.
use base::{Row, UnixTime, Version};
use factor::{Backoff, Cap, Closed, ErrorKind, FreeAttempts, Record, Throttle, Wait};

fn out_of_range<T>(r: Result<T, factor::Error>) -> bool {
    matches!(r, Err(e) if e.kind() == ErrorKind::OutOfRange)
}

const LAST: u64 = 10_000;

/// When a throttle under `free`, `wait` and `cap` reopens for `count` attempts last made at `LAST`, asked at `LAST`:
/// `None` when it permits at once.
fn reopens(
    free: FreeAttempts,
    wait: Wait,
    cap: Cap,
    count: u32,
) -> Result<Option<UnixTime>, Box<dyn std::error::Error>> {
    let mut bytes = vec![1, 0];
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(&LAST.to_be_bytes());
    let Record::Attempts(a) = Record::decode(&bytes)? else {
        return Err("not an attempts row".into());
    };
    let t = Throttle::new(Backoff::new(free, wait, cap));
    Ok(
        t.check(Some(Row::new(&a, Version::new(1))), UnixTime::new(LAST))
            .err()
            .map(|closed| match closed {
                Closed::Wait(until) => until,
                _ => UnixTime::new(0),
            }),
    )
}

#[test]
fn policy_bounds() -> Result<(), Box<dyn std::error::Error>> {
    assert!(out_of_range(FreeAttempts::new(0)));
    assert!(out_of_range(FreeAttempts::new(11)));
    assert!(out_of_range(Wait::new(0)));
    assert!(out_of_range(Wait::new(3_601)));
    assert!(out_of_range(Cap::new(3_599)));
    assert!(out_of_range(Cap::new(86_401)));
    let (wait, cap) = (Wait::new(60)?, Cap::new(3_600)?);
    // the bounds of FreeAttempts: that many attempts pass, the next one waits the first wait
    for free in [1, 10] {
        let f = FreeAttempts::new(free)?;
        assert_eq!(reopens(f, wait, cap, free - 1)?, None, "{free} free");
        assert_eq!(
            reopens(f, wait, cap, free)?,
            Some(UnixTime::new(LAST + 60)),
            "{free} free"
        );
    }
    // the bounds of Wait are the first wait itself
    for secs in [1, 3_600] {
        assert_eq!(
            reopens(FreeAttempts::new(1)?, Wait::new(secs)?, cap, 1)?,
            Some(UnixTime::new(LAST + secs)),
            "wait {secs}"
        );
    }
    // the bounds of Cap are the longest wait, reached by saturating doubling
    for secs in [3_600, 86_400] {
        assert_eq!(
            reopens(
                FreeAttempts::new(1)?,
                Wait::new(3_600)?,
                Cap::new(secs)?,
                40
            )?,
            Some(UnixTime::new(LAST + secs)),
            "cap {secs}"
        );
    }
    Ok(())
}

#[test]
fn no_row_permits() -> Result<(), factor::Error> {
    let strict = Throttle::new(Backoff::new(
        FreeAttempts::new(1)?,
        Wait::new(1)?,
        Cap::new(3_600)?,
    ));
    for now in [0, 1, u64::MAX].map(UnixTime::new) {
        assert_eq!(strict.check(None, now).map(|p| p.clock_fault()), Ok(false));
    }
    Ok(())
}

#[test]
fn a_row_from_a_fast_clock_is_released() -> Result<(), Box<dyn std::error::Error>> {
    let t = Throttle::new(Backoff::new(
        FreeAttempts::new(2)?,
        Wait::new(60)?,
        Cap::new(3_600)?,
    ));
    let now = 1_000u64;
    let at = |last: u64| -> Result<Closed, Box<dyn std::error::Error>> {
        let mut bytes = vec![1, 0];
        bytes.extend_from_slice(&9u32.to_be_bytes());
        bytes.extend_from_slice(&last.to_be_bytes());
        let Record::Attempts(a) = Record::decode(&bytes)? else {
            return Err("not an attempts row".into());
        };
        let row = Row::new(&a, Version::new(7));
        Ok(t.check(Some(row), UnixTime::new(now))
            .map(drop)
            .err()
            .unwrap_or(Closed::Wait(UnixTime::new(0))))
    };
    // a `last` 100 years ahead is released at once; anything up to a day ahead is skew and waits
    assert_eq!(
        at(now + 100 * 365 * 86_400)?,
        Closed::Wait(UnixTime::new(0))
    );
    assert_eq!(at(now + 3_600)?, Closed::Wait(UnixTime::new(now + 7_200)));
    assert_eq!(at(now + 3_601)?, Closed::Wait(UnixTime::new(now + 7_201)));
    let day = now + 86_400;
    assert_eq!(at(day)?, Closed::Wait(UnixTime::new(day + 3_600)));
    assert_eq!(at(day + 1)?, Closed::Wait(UnixTime::new(0)));
    Ok(())
}
