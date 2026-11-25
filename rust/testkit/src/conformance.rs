#![expect(
    clippy::panic,
    clippy::disallowed_macros,
    reason = "a harness reports a failed claim by panicking"
)]
use std::fmt::Debug;

use base::{
    Builder, Conflict, Effect, Failure, Pending, Receipt, Row, Slot, Store, StoreKey, UnixTime,
};

use crate::{Seeded, seeded};

/// Proves a concrete store honours the `Effect` obligation; run it on the exact apply path a shell uses.
/// `fresh` makes an empty store; `key(n)` must be injective, increasing in `n` and inside one transaction
/// domain for `n < 128`; `record(n)` must differ for different `n`. A failure panics with the case name.
pub fn store_conformance<K, R, S>(
    mut fresh: impl FnMut() -> S,
    key: impl Fn(u8) -> K,
    record: impl Fn(u8) -> R,
) where
    K: StoreKey + Debug,
    R: Clone + PartialEq + Debug,
    S: Store<K, R>,
    S::Error: Debug,
{
    let mut c = Case {
        name: "",
        e: seeded(7),
        key: &key,
        record: &record,
        now: UnixTime::new(1_000),
    };
    c.name = "atomic";
    c.atomic(&mut fresh());
    c.name = "fails_after_write";
    c.fails_after_write(&mut fresh());
    c.name = "expect_shared";
    c.expect_shared(&mut fresh());
    c.name = "disjoint";
    c.disjoint(&mut fresh());
    c.name = "reapply";
    c.reapply(&mut fresh());
    c.name = "reused_id";
    c.reused_id(&mut fresh());
    c.name = "conflict_not_applied";
    c.conflict_not_applied(&mut fresh());
    c.name = "duplicate_create";
    c.duplicate_create(&mut fresh());
    c.name = "expired";
    c.expired(&mut fresh());
    c.name = "recreate";
    c.recreate(&mut fresh());
    c.name = "at_bound";
    c.at_bound(&mut fresh());
}

struct Case<'a, K, R> {
    name: &'static str,
    e: Seeded,
    key: &'a dyn Fn(u8) -> K,
    record: &'a dyn Fn(u8) -> R,
    now: UnixTime,
}

impl<K: StoreKey + Debug, R: Clone + PartialEq + Debug> Case<'_, K, R> {
    fn k(&self, n: u8) -> K {
        (self.key)(n)
    }

    fn r(&self, n: u8) -> R {
        (self.record)(n)
    }

    fn fail(&self, what: &str) -> String {
        format!("{}: {what}", self.name)
    }

    fn build(&mut self, f: impl FnOnce(Builder<K, R>, &Self) -> Builder<K, R>) -> Effect<K, R> {
        let b = Effect::builder(&mut self.e);
        f(b, self)
            .build()
            .unwrap_or_else(|e| panic!("{}: conformance effect builds: {e}", self.name))
    }

    fn apply<S: Store<K, R>>(&self, s: &mut S, e: &Effect<K, R>) -> Result<Receipt, Conflict<K>>
    where
        S::Error: Debug,
    {
        s.apply(e, self.now)
            .unwrap_or_else(|err| panic!("{}: apply outcome known: {err:?}", self.name))
    }

    fn applies<S: Store<K, R>>(&self, s: &mut S, e: &Effect<K, R>, what: &str)
    where
        S::Error: Debug,
    {
        let receipt = self
            .apply(s, e)
            .unwrap_or_else(|_| panic!("{}", self.fail(what)));
        assert_eq!(
            receipt.effect_id(),
            e.id(),
            "{}",
            self.fail("an apply answers its own effect's receipt")
        );
    }

    fn conflicts<S: Store<K, R>>(&self, s: &mut S, e: &Effect<K, R>, want: Vec<(K, Failure)>)
    where
        S::Error: Debug,
    {
        let Err(conflict) = self.apply(s, e) else {
            panic!(
                "{}",
                self.fail(&format!("applied; want a conflict on {want:?}"))
            );
        };
        let mut got = conflict.failures().to_vec();
        got.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            got,
            want,
            "{}",
            self.fail("conflict names each failed guard")
        );
    }

    fn row<S: Store<K, R>>(&self, s: &mut S, n: u8) -> Option<Row<R>>
    where
        S::Error: Debug,
    {
        let k = self.k(n);
        let rows = s
            .load(std::slice::from_ref(&k), self.now)
            .unwrap_or_else(|err| panic!("{}: load: {err:?}", self.name));
        match rows.get(&k) {
            Some(Slot::Row(row)) => Some(row.clone()),
            Some(Slot::Absent) => None,
            _ => panic!("{}", self.fail("loaded key reported and decodes")),
        }
    }

    fn holds<S: Store<K, R>>(&self, s: &mut S, n: u8, want: Option<&Row<R>>, what: &str)
    where
        S::Error: Debug,
    {
        let got = self.row(s, n).map(|r| (r.version(), r.into_record()));
        let want = want.map(|r| (r.version(), r.record().clone()));
        assert_eq!(got, want, "{}", self.fail(what));
    }

    fn seed<const N: usize, S: Store<K, R>>(&mut self, s: &mut S, ns: [u8; N]) -> [Row<R>; N]
    where
        S::Error: Debug,
    {
        let e = self.build(|b, c| ns.iter().fold(b, |b, &n| b.create(c.k(n), c.r(n), None)));
        self.applies(s, &e, "seed rows apply");
        ns.map(|n| {
            self.row(s, n)
                .unwrap_or_else(|| panic!("{}", self.fail("seeded row loads")))
        })
    }

    // failing guards sort first, so a store that stops at the first failure still writes nothing here
    fn atomic<S: Store<K, R>>(&mut self, s: &mut S)
    where
        S::Error: Debug,
    {
        let [r1, r2, r3, r4] = &self.seed(s, [1, 2, 3, 4]);
        let broken = self.build(|b, c| {
            b.consume(c.k(0))
                .expect_absent(c.k(1))
                .update(c.k(2), r2, c.r(9), None)
                .delete(c.k(3), r3)
                .consume(c.k(4))
                .create(c.k(6), c.r(6), None)
        });
        self.conflicts(
            s,
            &broken,
            vec![(self.k(0), Failure::Missing), (self.k(1), Failure::Present)],
        );
        for (n, row) in [(1, r1), (2, r2), (3, r3), (4, r4)] {
            self.holds(s, n, Some(row), "a conflicted effect writes nothing");
        }
        self.holds(s, 6, None, "a conflicted effect writes nothing");
        let whole = self.build(|b, c| {
            b.update(c.k(1), r1, c.r(9), None)
                .consume(c.k(2))
                .delete(c.k(3), r3)
                .create(c.k(5), c.r(5), None)
        });
        self.applies(s, &whole, "holding guards apply");
        let after = self
            .row(s, 1)
            .unwrap_or_else(|| panic!("{}", self.fail("updated row")));
        assert!(
            after.record() == &self.r(9) && after.version() != r1.version(),
            "{}",
            self.fail("an update writes a new version")
        );
        self.holds(s, 2, None, "consume deletes");
        self.holds(s, 3, None, "delete deletes");
        self.holds(s, 4, Some(r4), "a row outside the effect stands");
        assert_eq!(
            self.row(s, 5).map(Row::into_record),
            Some(self.r(5)),
            "{}",
            self.fail("create writes")
        );
        let stale = self.build(|b, c| b.expect(c.k(1), r1));
        self.conflicts(s, &stale, vec![(self.k(1), Failure::Changed)]);
    }

    fn fails_after_write<S: Store<K, R>>(&mut self, s: &mut S)
    where
        S::Error: Debug,
    {
        let [r1] = &self.seed(s, [1]);
        let e = self.build(|b, c| b.create(c.k(0), c.r(0), None).expect_absent(c.k(1)));
        self.conflicts(s, &e, vec![(self.k(1), Failure::Present)]);
        self.holds(
            s,
            0,
            None,
            "a write before the failing guard is rolled back",
        );
        self.holds(s, 1, Some(r1), "the guarded row is untouched");
    }

    // guard-only effects, so a store that bumps every guarded row fails here, not in `disjoint`
    fn expect_shared<S: Store<K, R>>(&mut self, s: &mut S)
    where
        S::Error: Debug,
    {
        let [row] = &self.seed(s, [0]);
        let a = self.build(|b, c| b.expect(c.k(0), row));
        let b = self.build(|b, c| b.expect(c.k(0), row));
        self.applies(s, &a, "the first expect applies");
        self.applies(s, &b, "a second expect of the same row applies");
        self.holds(s, 0, Some(row), "expect writes nothing");
    }

    fn disjoint<S: Store<K, R>>(&mut self, s: &mut S)
    where
        S::Error: Debug,
    {
        let [r0, r1] = &self.seed(s, [0, 1]);
        let a = self.build(|b, c| b.update(c.k(0), r0, c.r(5), None));
        let b = self.build(|b, c| b.delete(c.k(1), r1).create(c.k(2), c.r(2), None));
        self.applies(s, &a, "the first of two disjoint effects applies");
        self.applies(s, &b, "the second of two disjoint effects applies");
        assert_eq!(
            self.row(s, 0).map(Row::into_record),
            Some(self.r(5)),
            "{}",
            self.fail("both effects' writes stand")
        );
        self.holds(s, 1, None, "both effects' writes stand");
    }

    fn reapply<S: Store<K, R>>(&mut self, s: &mut S)
    where
        S::Error: Debug,
    {
        let created = self.build(|b, c| b.create(c.k(0), c.r(0), None));
        let pending = Pending::new('v', created);
        self.applies(s, pending.effect(), "first apply");
        let first = self.row(s, 0);
        let receipt = self
            .apply(s, pending.effect())
            .unwrap_or_else(|_| panic!("{}", self.fail("an applied id answers Ok")));
        assert_eq!(
            pending.settle(receipt).ok(),
            Some('v'),
            "{}",
            self.fail("the receipt settles the effect")
        );
        self.holds(s, 0, first.as_ref(), "nothing written twice");
    }

    // entropy that repeats gives two effects one id; answering the second Ok would settle it with nothing written
    fn reused_id<S: Store<K, R>>(&mut self, s: &mut S)
    where
        S::Error: Debug,
    {
        let saved = std::mem::replace(&mut self.e, seeded(1));
        let first = self.build(|b, c| b.create(c.k(0), c.r(0), None));
        self.e = seeded(1);
        let second = self.build(|b, c| b.create(c.k(1), c.r(1), None));
        self.e = saved;
        assert_eq!(first.id(), second.id(), "{}", self.fail("one seed, one id"));
        self.applies(s, &first, "the first apply");
        assert!(
            !matches!(s.apply(&second, self.now), Ok(Ok(_))),
            "{}",
            self.fail("a reused id with different keys is not Ok")
        );
    }

    fn conflict_not_applied<S: Store<K, R>>(&mut self, s: &mut S)
    where
        S::Error: Debug,
    {
        self.seed(s, [0]);
        let e = self.build(|b, c| b.expect_absent(c.k(0)).create(c.k(1), c.r(1), None));
        self.conflicts(s, &e, vec![(self.k(0), Failure::Present)]);
        let clear = self.build(|b, c| b.consume(c.k(0)));
        self.applies(s, &clear, "clearing the conflict applies");
        self.applies(
            s,
            &e,
            "a conflicted id is not recorded, so it applies later",
        );
        assert_eq!(
            self.row(s, 1).map(Row::into_record),
            Some(self.r(1)),
            "{}",
            self.fail("the later apply writes")
        );
    }

    fn duplicate_create<S: Store<K, R>>(&mut self, s: &mut S)
    where
        S::Error: Debug,
    {
        let a = self.build(|b, c| b.create(c.k(0), c.r(0), None));
        let b = self.build(|b, c| b.create(c.k(0), c.r(1), None));
        self.applies(s, &a, "first create");
        let first = self.row(s, 0);
        self.conflicts(s, &b, vec![(self.k(0), Failure::Present)]);
        self.holds(s, 0, first.as_ref(), "the first create stands");
    }

    fn expired<S: Store<K, R>>(&mut self, s: &mut S)
    where
        S::Error: Debug,
    {
        let start = self.now;
        let deadline = start.saturating_add(1);
        let [r2] = &self.seed(s, [2]);
        let e = self.build(|b, c| {
            b.create(c.k(0), c.r(0), Some(deadline))
                .create(c.k(1), c.r(1), Some(deadline))
                .update(c.k(2), r2, c.r(3), Some(deadline))
        });
        self.applies(s, &e, "create and update with a deadline");
        let [seen, updated] = [1, 2].map(|n| {
            self.row(s, n)
                .unwrap_or_else(|| panic!("{}", self.fail("live before its deadline")))
        });
        self.now = deadline;
        self.holds(s, 0, None, "absent to load at its deadline");
        self.holds(s, 2, None, "an update's deadline holds");
        let stale = self.build(|b, c| b.expect(c.k(1), &seen));
        self.conflicts(s, &stale, vec![(self.k(1), Failure::Missing)]);
        let consume = self.build(|b, c| b.consume(c.k(0)));
        self.conflicts(s, &consume, vec![(self.k(0), Failure::Missing)]);
        let update = self.build(|b, c| b.update(c.k(1), &seen, c.r(4), None));
        self.conflicts(s, &update, vec![(self.k(1), Failure::Missing)]);
        let delete = self.build(|b, c| b.delete(c.k(2), &updated));
        self.conflicts(s, &delete, vec![(self.k(2), Failure::Missing)]);
        let again = self.build(|b, c| b.create(c.k(0), c.r(2), None).create(c.k(1), c.r(1), None));
        self.applies(s, &again, "Absent holds over an unpurged expired row");
        // same record as before, so only a fresh version tells the incarnations apart
        let aba = self.build(|b, c| b.expect(c.k(1), &seen));
        self.conflicts(s, &aba, vec![(self.k(1), Failure::Changed)]);
        self.now = start;
    }

    fn recreate<S: Store<K, R>>(&mut self, s: &mut S)
    where
        S::Error: Debug,
    {
        let [row] = &self.seed(s, [0]);
        let gone = self.build(|b, c| b.delete(c.k(0), row));
        self.applies(s, &gone, "delete");
        self.seed(s, [0]);
        let stale = self.build(|b, c| b.update(c.k(0), row, c.r(1), None));
        self.conflicts(s, &stale, vec![(self.k(0), Failure::Changed)]);
    }

    fn at_bound<S: Store<K, R>>(&mut self, s: &mut S)
    where
        S::Error: Debug,
    {
        let guards = self.build(|b, c| (0..128).fold(b, |b, n| b.expect_absent(c.k(n))));
        self.applies(s, &guards, "128 guards apply");
        let creates = self.build(|b, c| (0..64).fold(b, |b, n| b.create(c.k(n), c.r(n), None)));
        self.applies(s, &creates, "64 creates apply");
        let seen = self.all(s);
        let updates = self.build(|b, c| {
            seen.iter()
                .zip(0..)
                .fold(b, |b, (row, n)| b.update(c.k(n), row, c.r(n + 64), None))
        });
        self.applies(s, &updates, "64 updates apply");
        let seen = self.all(s);
        assert!(
            seen.iter()
                .zip(0..)
                .all(|(row, n)| row.record() == &self.r(n + 64)),
            "{}",
            self.fail("every row updated")
        );
        let deletes = self.build(|b, c| {
            seen.iter()
                .zip(0..)
                .fold(b, |b, (row, n)| b.delete(c.k(n), row))
        });
        self.applies(s, &deletes, "64 deletes apply");
        assert!(
            (0..64).all(|n| self.row(s, n).is_none()),
            "{}",
            self.fail("every row deleted")
        );
        let again = self.build(|b, c| (0..64).fold(b, |b, n| b.create(c.k(n), c.r(n), None)));
        self.applies(s, &again, "64 creates apply over deleted rows");
        let consumes = self.build(|b, c| (0..64).fold(b, |b, n| b.consume(c.k(n))));
        self.applies(s, &consumes, "64 consumes apply");
        assert!(
            (0..64).all(|n| self.row(s, n).is_none()),
            "{}",
            self.fail("every row consumed")
        );
    }

    // rows 0 to 63, each present
    fn all<S: Store<K, R>>(&self, s: &mut S) -> Vec<Row<R>>
    where
        S::Error: Debug,
    {
        (0..64)
            .map(|n| {
                self.row(s, n)
                    .unwrap_or_else(|| panic!("{}", self.fail("every row written")))
            })
            .collect()
    }
}
