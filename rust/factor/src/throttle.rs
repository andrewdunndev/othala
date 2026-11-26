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
    /// Accepts 0 to 10.
    pub const fn new(attempts: u32) -> Result<Self, Error> {
        within(attempts <= 10, Self(attempts))
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

    fn until(self, seen: Attempts) -> Option<UnixTime> {
        let doublings = seen.count.checked_sub(self.free.0)?;
        let wait = 2u64.saturating_pow(doublings).saturating_mul(self.first.0);
        Some(seen.last.saturating_add(wait.min(self.cap.0)))
    }
}

impl Throttle {
    /// A throttle under `policy`.
    pub const fn new(policy: Backoff) -> Self {
        Self {
            policy: Some(policy),
        }
    }

    /// Permits at every count; verdicts still count.
    pub const fn unlimited() -> Self {
        Self { policy: None }
    }

    /// A permit, or the time from which one is issued; the wait is decided here at `now`, never by a store expiry.
    pub fn check(&self, attempts: Option<Row<&Attempts>>, now: UnixTime) -> Result<Permit, Closed> {
        let seen = attempts.map(|row| (row.version(), **row.record()));
        match self.policy.zip(seen).and_then(|(p, (_, a))| p.until(a)) {
            Some(until) if now < until => Err(Closed::Wait(until)),
            _ => Ok(Permit { seen, at: now }),
        }
    }

    /// The one way the count falls; the consumer merges it into the session effect that completes a login.
    pub fn reset(attempts: Row<&Attempts>, e: &mut impl Entropy) -> Effect {
        Effect::deleted(e, Key::Attempts, &attempts)
    }
}

impl Permit {
    pub(crate) const fn time(&self) -> UnixTime {
        self.at
    }

    /// Every verdict's effect starts here: the count one higher, guarded at the version this permit saw.
    pub(crate) fn count(self, e: &mut impl Entropy) -> Builder<Key, Record> {
        let next = |count: u32| {
            Record::Attempts(Attempts {
                count,
                last: self.at,
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
        let permit = Throttle::unlimited().check(read.as_ref().map(seen), UnixTime::new(now));
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
        assert_eq!(check(Throttle::unlimited(), &end, 0), Ok(()));
        Ok(())
    }

    #[test]
    fn verdicts_only_increment() {
        let (mut store, mut e) = (Mem::new(), seeded(3));
        for (count, now) in [(1, 10), (2, 20), (3, 5)] {
            let last = UnixTime::new(now);
            assert_eq!(
                verdict(&mut store, &mut e, now),
                Some(Attempts { count, last })
            );
        }
        let top = row(u32::MAX, LAST);
        let effect = Throttle::unlimited()
            .check(Some(seen(&top)), LAST)
            .map(|p| p.count(&mut e).build());
        let put = Record::Attempts(*top.record());
        assert!(matches!(effect, Ok(Ok(ef)) if ef.puts().all(|(_, r, _)| *r == put)));
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
