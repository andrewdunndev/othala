use base::{Builder, Entropy, Row, UnixTime, Version};

use crate::{Effect, Error, ErrorKind, Key, Record};

/// The subject's attempt count since the last reset, and when the last one was made; stored under [`crate::Key::Attempts`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attempts {
    count: u32,
    last: UnixTime,
}

impl Attempts {
    pub(crate) const fn new(count: u32, last: UnixTime) -> Self {
        Self { count, last }
    }

    pub(crate) const fn parts(&self) -> (u32, UnixTime) {
        (self.count, self.last)
    }
}

/// How many attempts after a reset wait for nothing: 1 to 10.
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
    policy: Backoff,
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
    fault: bool,
}

// a stamp this far ahead is a fault, not skew: smaller skews stay fail-closed so two skewed nodes cannot trade permits
const FAULT_FLOOR: u64 = 86_400;

const fn within<T: Copy>(ok: bool, value: T) -> Result<T, Error> {
    if ok {
        Ok(value)
    } else {
        Err(Error {
            kind: ErrorKind::OutOfRange,
        })
    }
}

impl FreeAttempts {
    /// Accepts 1 to 10.
    pub const fn new(attempts: u32) -> Result<Self, Error> {
        within(matches!(attempts, 1..=10), Self(attempts))
    }
}

impl Wait {
    /// Accepts 1 to 3,600 seconds.
    pub const fn new(secs: u64) -> Result<Self, Error> {
        within(matches!(secs, 1..=3_600), Self(secs))
    }
}

impl Cap {
    /// Accepts 3,600 to 86,400 seconds.
    pub const fn new(secs: u64) -> Result<Self, Error> {
        within(matches!(secs, 3_600..=86_400), Self(secs))
    }
}

impl Backoff {
    /// Every `Wait` is within every `Cap`, so this cannot fail.
    pub const fn new(free: FreeAttempts, first: Wait, cap: Cap) -> Self {
        Self { free, first, cap }
    }

    fn faulted(self, last: UnixTime, now: UnixTime) -> bool {
        last > now.saturating_add(self.cap.0.max(FAULT_FLOOR))
    }

    fn until(self, seen: Attempts, now: UnixTime) -> Option<UnixTime> {
        let doublings = seen.count.checked_sub(self.free.0)?;
        let wait = 2u64.saturating_pow(doublings).saturating_mul(self.first.0);
        let due = seen.last.saturating_add(wait.min(self.cap.0));
        // a `last` more than the fault threshold ahead is a clock fault, released here and restamped by the next count
        (!self.faulted(seen.last, now)).then_some(due)
    }
}

impl Throttle {
    /// A throttle under `policy`.
    pub const fn new(policy: Backoff) -> Self {
        Self { policy }
    }

    /// A permit, or the time from which one is issued; the wait is decided here at `now`, never by a store expiry.
    pub fn check(&self, attempts: Option<Row<&Attempts>>, now: UnixTime) -> Result<Permit, Closed> {
        let seen = attempts.map(|row| (row.version(), **row.record()));
        if let Some(until) = seen.and_then(|(_, a)| self.policy.until(a, now))
            && now < until
        {
            return Err(Closed::Wait(until));
        }
        let mut fault = false;
        let seen = seen.map(|(v, a)| {
            if self.policy.faulted(a.last, now) {
                fault = true;
                (v, Attempts { last: now, ..a })
            } else {
                (v, a)
            }
        });
        Ok(Permit {
            seen,
            at: now,
            fault,
        })
    }

    /// The one way the count falls; the consumer merges it into the session effect that completes a login.
    pub fn reset(attempts: Row<&Attempts>, e: &mut impl Entropy) -> Effect {
        Effect::deleted(e, Key::Attempts, &attempts)
    }
}

impl Permit {
    /// True when the stored stamp was ahead of the clock by more than a day and was released and restamped; hosts alert on it.
    pub const fn clock_fault(&self) -> bool {
        self.fault
    }

    pub(crate) const fn time(&self) -> UnixTime {
        self.at
    }

    /// Every verdict's effect starts here: the count one higher, guarded at the version this permit saw.
    pub(crate) fn count(self, e: &mut impl Entropy) -> Builder<Key, Record> {
        let next = |count: u32| {
            Record::Attempts(Attempts {
                count,
                last: self.seen.map_or(self.at, |(_, a)| a.last.max(self.at)),
            })
        };
        match self.seen {
            Some((version, seen)) => Effect::builder(e).update(
                Key::Attempts,
                &Row::new((), version),
                next(seen.count.saturating_add(1)),
                None,
            ),
            None => Effect::builder(e).create(Key::Attempts, next(1), None),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use base::{Guard, Row, Slot, Store, UnixTime, Version};
    use testkit::{MemStore, Seeded, seeded};

    use super::{Attempts, Backoff, Cap, Closed, FreeAttempts, Throttle, Wait};
    use crate::{Error, Key, Record};

    type Mem = MemStore<Key, Record>;
    const LAST: UnixTime = UnixTime::new(1_000);
    const KEY: &Key = &Key::Attempts;

    // policy values inside the CONTRACT's R7 ranges, through the public constructors
    fn throttle() -> Result<Throttle, Error> {
        let policy = Backoff::new(FreeAttempts::new(2)?, Wait::new(60)?, Cap::new(3_600)?);
        Ok(Throttle::new(policy))
    }

    // ten free attempts, so a test that only counts is never closed
    fn roomy() -> Result<Throttle, Error> {
        let policy = Backoff::new(FreeAttempts::new(10)?, Wait::new(1)?, Cap::new(3_600)?);
        Ok(Throttle::new(policy))
    }

    fn row(count: u32, last: UnixTime) -> Row<Attempts> {
        Row::new(Attempts { count, last }, Version::new(7))
    }

    fn seen(row: &Row<Attempts>) -> Row<&Attempts> {
        Row::new(row.record(), row.version())
    }

    fn check(t: Throttle, row: &Row<Attempts>, now: u64) -> Result<(), Closed> {
        t.check(Some(seen(row)), UnixTime::new(now)).map(drop)
    }

    fn load(store: &mut Mem) -> Option<Row<Attempts>> {
        match store.load(&[Key::Attempts], LAST).ok()?.get(KEY)? {
            Slot::Row(r) => match r.record() {
                Record::Attempts(a) => Some(Row::new(*a, r.version())),
                _ => None,
            },
            _ => None,
        }
    }

    // one verdict's effect as every verifier starts it, from a permit issued at `now`, then applied
    fn verdict(store: &mut Mem, e: &mut Seeded, now: u64) -> Option<Attempts> {
        let read = load(store);
        let permit = roomy()
            .ok()?
            .check(read.as_ref().map(seen), UnixTime::new(now));
        let effect = permit.ok()?.count(e).build().ok()?;
        let guard = read.map_or(Guard::Absent(KEY), |r| Guard::Unchanged(KEY, r.version()));
        assert_eq!(effect.guards().collect::<Vec<_>>(), [guard]);
        assert_eq!(effect.deletes().count(), 0);
        assert!(
            effect
                .puts()
                .all(|(k, _, expiry)| k == KEY && expiry.is_none())
        );
        store.apply(&effect, LAST).ok()?.ok()?;
        load(store).map(|r| *r.record())
    }

    #[test]
    fn throttle_schedule() -> Result<(), Error> {
        let t = throttle()?;
        for count in [0, 1] {
            assert_eq!(check(t, &row(count, LAST), LAST.secs()), Ok(()));
        }
        let waits = [
            (2, 60),
            (3, 120),
            (4, 240),
            (7, 1_920),
            (8, 3_600),
            (64, 3_600),
            (u32::MAX, 3_600),
        ];
        for (count, wait) in waits {
            let until = LAST.secs() + wait;
            let closed = Err(Closed::Wait(UnixTime::new(until)));
            assert_eq!(check(t, &row(count, LAST), until - 1), closed);
            assert_eq!(check(t, &row(count, LAST), until), Ok(()));
        }
        let end = row(u32::MAX, UnixTime::new(u64::MAX - 1));
        assert_eq!(
            check(t, &end, u64::MAX - 1),
            Err(Closed::Wait(UnixTime::new(u64::MAX)))
        );
        assert_eq!(check(t, &end, u64::MAX), Ok(()));
        // a stamp this far ahead is a clock fault, released at once
        assert_eq!(check(t, &end, 0), Ok(()));
        Ok(())
    }

    #[test]
    fn a_faulted_row_is_restamped_to_the_present() -> Result<(), Error> {
        let mut e = seeded(5);
        let ahead = UnixTime::new(LAST.secs() + 100 * 365 * 86_400);
        let r = row(9, ahead);
        let permit = throttle()?.check(Some(seen(&r)), LAST);
        let effect = permit.ok().map(|p| p.count(&mut e).build());
        let put = Record::Attempts(Attempts {
            count: 10,
            last: LAST,
        });
        assert!(matches!(effect, Some(Ok(ef)) if ef.puts().all(|(_, rec, _)| *rec == put)));
        Ok(())
    }

    #[test]
    fn a_fault_is_flagged_and_a_clean_permit_is_not() -> Result<(), Error> {
        let t = throttle()?;
        let ahead = row(9, UnixTime::new(LAST.secs() + 100 * 365 * 86_400));
        let behind = row(0, LAST);
        assert!(
            t.check(Some(seen(&ahead)), LAST)
                .is_ok_and(|p| p.clock_fault())
        );
        assert!(
            t.check(Some(seen(&behind)), LAST)
                .is_ok_and(|p| !p.clock_fault())
        );
        assert!(t.check(None, LAST).is_ok_and(|p| !p.clock_fault()));
        // a day and a second ahead is a fault; exactly a day ahead is not
        let edge = |d: u64| row(9, UnixTime::new(LAST.secs() + d));
        let day = edge(86_400);
        assert!(t.check(Some(seen(&day)), LAST).is_err());
        let over = edge(86_401);
        assert!(
            t.check(Some(seen(&over)), LAST)
                .is_ok_and(|p| p.clock_fault())
        );
        Ok(())
    }

    // two nodes whose clocks differ by more than the cap, less than the fault threshold, trading attempts one second apart
    #[test]
    fn skewed_nodes_cannot_trade_permits() -> Result<(), Error> {
        let (mut store, mut e) = (Mem::new(), seeded(8));
        let t = throttle()?;
        let skew = 12 * 3_600;
        let mut permits = 0;
        for i in 0..200u64 {
            let now = UnixTime::new(1_000_000 + i + if i % 2 == 0 { skew } else { 0 });
            let read = load(&mut store);
            let Ok(permit) = t.check(read.as_ref().map(seen), now) else {
                continue;
            };
            assert!(!permit.clock_fault());
            permits += 1;
            let Ok(effect) = permit.count(&mut e).build() else {
                continue;
            };
            assert!(matches!(store.apply(&effect, LAST), Ok(Ok(_))));
        }
        assert!(permits <= 4, "{permits} permits");
        Ok(())
    }

    #[test]
    fn a_row_within_one_cap_ahead_keeps_its_stamp() -> Result<(), Error> {
        let mut e = seeded(6);
        let last = UnixTime::new(LAST.secs() + 3_600);
        let r = row(0, last);
        let effect = throttle()?
            .check(Some(seen(&r)), LAST)
            .ok()
            .map(|p| p.count(&mut e).build());
        let put = Record::Attempts(Attempts { count: 1, last });
        assert!(matches!(effect, Some(Ok(ef)) if ef.puts().all(|(_, rec, _)| *rec == put)));
        Ok(())
    }

    #[test]
    fn verdicts_only_increment() {
        let (mut store, mut e) = (Mem::new(), seeded(3));
        for (count, now, stamp) in [(1, 10, 10), (2, 20, 20), (3, 5, 20)] {
            let last = UnixTime::new(stamp);
            assert_eq!(
                verdict(&mut store, &mut e, now),
                Some(Attempts { count, last })
            );
        }
        let top = row(u32::MAX, LAST);
        // the count saturates, and the stamp moves to the permit's time once the wait is over
        let at = UnixTime::new(LAST.secs() + 3_600);
        let effect = throttle()
            .map(|t| t.check(Some(seen(&top)), at))
            .map(|r| r.map(|p| p.count(&mut e).build()));
        let put = Record::Attempts(Attempts {
            count: u32::MAX,
            last: at,
        });
        assert!(matches!(effect, Ok(Ok(Ok(ef))) if ef.puts().all(|(_, r, _)| *r == put)));
    }

    #[test]
    fn reset_only() {
        let (mut store, mut e) = (Mem::new(), seeded(4));
        assert!(verdict(&mut store, &mut e, 1).is_some());
        let stale = load(&mut store).map(|r| Throttle::reset(seen(&r), &mut e));
        let read = load(&mut store).map(|r| (r.version(), Throttle::reset(seen(&r), &mut e)));
        assert!(matches!(&read, Some((v, reset))
            if reset.guards().eq([Guard::Unchanged(KEY, *v)])
            && reset.deletes().eq([KEY])
            && reset.puts().count() == 0));
        assert!(verdict(&mut store, &mut e, 2).is_some());
        assert!(stale.is_some_and(|s| matches!(store.apply(&s, LAST), Ok(Err(_)))));
        let fresh = load(&mut store).map(|r| Throttle::reset(seen(&r), &mut e));
        assert!(fresh.is_some_and(|f| matches!(store.apply(&f, LAST), Ok(Ok(_)))));
        assert!(store.contents(LAST).is_empty());
    }
}
