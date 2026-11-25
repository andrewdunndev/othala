use std::fmt::Debug;

use base::{
    Builder, Conflict, Effect, Failure, MAX_EFFECT_SIZE, Pending, Receipt, Row, Slot, Store,
    StoreKey, UnixTime,
};

use crate::{Seeded, seeded};

/// Proves a concrete store honours the `Effect` obligation; run it on the exact apply path a shell uses.
/// `fresh` makes an empty store; `key(n)` must be injective, increasing in `n` and inside one transaction
/// domain for `n < 128`; `record(n)` must differ for different `n`.
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
        e: seeded(7),
        key: &key,
        record: &record,
        now: UnixTime::new(1_000),
    };
    c.atomic(&mut fresh());
    c.fails_after_write(&mut fresh());
    c.expect_shared(&mut fresh());
    c.disjoint(&mut fresh());
    c.reapply(&mut fresh());
    c.duplicate_create(&mut fresh());
    c.expired(&mut fresh());
    c.recreate(&mut fresh());
    c.at_bound(&mut fresh());
}

struct Case<'a, K, R> {
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

    fn build(&mut self, f: impl FnOnce(&mut Builder<K, R>, &Self)) -> Effect<K, R> {
        let mut b = Effect::builder(&mut self.e);
        f(&mut b, self);
        b.build().expect("conformance effect builds")
    }

    fn apply<S: Store<K, R>>(&self, s: &mut S, e: &Effect<K, R>) -> Result<Receipt, Conflict<K>>
    where
        S::Error: Debug,
    {
        s.apply(e, self.now).expect("apply outcome known")
    }

    fn row<S: Store<K, R>>(&self, s: &mut S, n: u8, now: UnixTime) -> Option<Row<R>>
    where
        S::Error: Debug,
    {
        let k = self.k(n);
        let rows = s.load(std::slice::from_ref(&k), now).expect("load");
        match rows.get(&k).expect("loaded key reported") {
            Slot::Row(row) => Some(row.clone()),
            Slot::Absent => None,
            _ => panic!("conformance rows decode"),
        }
    }

    fn live<S: Store<K, R>>(&self, s: &mut S, n: u8) -> Option<Row<R>>
    where
        S::Error: Debug,
    {
        self.row(s, n, self.now)
    }

    fn failures(&self, conflict: &Conflict<K>) -> Vec<(K, Failure)> {
        let mut f = conflict.failures().to_vec();
        f.sort_by(|a, b| a.0.cmp(&b.0));
        f
    }

    fn seed<const N: usize, S: Store<K, R>>(&mut self, s: &mut S, ns: [u8; N]) -> [Row<R>; N]
    where
        S::Error: Debug,
    {
        let e = self.build(|b, c| {
            for n in ns {
                b.create(c.k(n), c.r(n), None);
            }
        });
        assert!(self.apply(s, &e).is_ok(), "seed rows apply");
        ns.map(|n| self.live(s, n).expect("seeded row loads"))
    }

    fn atomic<S: Store<K, R>>(&mut self, s: &mut S)
    where
        S::Error: Debug,
    {
        let [r0, _, r2] = &self.seed(s, [0, 1, 2]);
        let broken = self.build(|b, c| {
            b.update(c.k(0), r0, c.r(9), None)
                .consume(c.k(5))
                .expect_absent(c.k(1))
                .create(c.k(6), c.r(6), None);
        });
        let conflict = self
            .apply(s, &broken)
            .expect_err("atomic: failing guards conflict");
        let want = vec![(self.k(1), Failure::Present), (self.k(5), Failure::Missing)];
        assert_eq!(
            self.failures(&conflict),
            want,
            "atomic: conflict names each failed guard"
        );
        assert_eq!(
            self.live(s, 0).map(Row::into_record),
            Some(self.r(0)),
            "atomic: nothing applied"
        );
        assert!(self.live(s, 6).is_none(), "atomic: nothing applied");
        let whole = self.build(|b, c| {
            b.update(c.k(0), r0, c.r(9), None)
                .consume(c.k(1))
                .delete(c.k(2), r2)
                .create(c.k(3), c.r(3), None);
        });
        assert!(
            self.apply(s, &whole).is_ok(),
            "atomic: holding guards apply"
        );
        let after = self.live(s, 0).expect("atomic: updated row");
        assert_eq!(
            (after.record(), after.version() == r0.version()),
            (&self.r(9), false),
            "atomic: new version"
        );
        assert!(
            self.live(s, 1).is_none() && self.live(s, 2).is_none(),
            "atomic: consume and delete"
        );
        assert_eq!(
            self.live(s, 3).map(Row::into_record),
            Some(self.r(3)),
            "atomic: create"
        );
        let stale = self.build(|b, c| {
            b.expect(c.k(0), r0);
        });
        let conflict = self
            .apply(s, &stale)
            .expect_err("atomic: stale version conflicts");
        assert_eq!(
            self.failures(&conflict),
            vec![(self.k(0), Failure::Changed)]
        );
    }

    fn fails_after_write<S: Store<K, R>>(&mut self, s: &mut S)
    where
        S::Error: Debug,
    {
        self.seed(s, [1]);
        let e = self.build(|b, c| {
            b.create(c.k(0), c.r(0), None).expect_absent(c.k(1));
        });
        assert!(self.apply(s, &e).is_err(), "fails_after_write: conflict");
        assert!(
            self.live(s, 0).is_none(),
            "fails_after_write: earlier write rolled back"
        );
    }

    fn expect_shared<S: Store<K, R>>(&mut self, s: &mut S)
    where
        S::Error: Debug,
    {
        let [row] = &self.seed(s, [0]);
        let a = self.build(|b, c| {
            b.expect(c.k(0), row).create(c.k(1), c.r(1), None);
        });
        let b = self.build(|b, c| {
            b.expect(c.k(0), row).create(c.k(2), c.r(2), None);
        });
        assert!(
            self.apply(s, &a).is_ok() && self.apply(s, &b).is_ok(),
            "expect_shared: both apply"
        );
    }

    fn disjoint<S: Store<K, R>>(&mut self, s: &mut S)
    where
        S::Error: Debug,
    {
        let [row, _] = &self.seed(s, [0, 1]);
        let a = self.build(|b, c| {
            b.update(c.k(0), row, c.r(5), None);
        });
        let b = self.build(|b, c| {
            b.consume(c.k(1)).create(c.k(2), c.r(2), None);
        });
        assert!(
            self.apply(s, &a).is_ok() && self.apply(s, &b).is_ok(),
            "disjoint: both apply"
        );
    }

    fn reapply<S: Store<K, R>>(&mut self, s: &mut S)
    where
        S::Error: Debug,
    {
        let created = self.build(|b, c| {
            b.create(c.k(0), c.r(0), None);
        });
        let pending = Pending::new('v', created);
        assert!(
            self.apply(s, pending.effect()).is_ok(),
            "reapply: first apply"
        );
        let first = self.live(s, 0).expect("reapply: row").version();
        let receipt = self
            .apply(s, pending.effect())
            .expect("reapply: an applied id answers Ok");
        assert_eq!(
            pending.settle(receipt).ok(),
            Some('v'),
            "reapply: receipt settles the effect"
        );
        assert_eq!(
            self.live(s, 0).map(|r| r.version()),
            Some(first),
            "reapply: nothing written twice"
        );
    }

    fn duplicate_create<S: Store<K, R>>(&mut self, s: &mut S)
    where
        S::Error: Debug,
    {
        let a = self.build(|b, c| {
            b.create(c.k(0), c.r(0), None);
        });
        let b = self.build(|b, c| {
            b.create(c.k(0), c.r(1), None);
        });
        assert!(self.apply(s, &a).is_ok(), "duplicate_create: first");
        let conflict = self
            .apply(s, &b)
            .expect_err("duplicate_create: Conflict, never Error");
        assert_eq!(
            self.failures(&conflict),
            vec![(self.k(0), Failure::Present)]
        );
    }

    fn expired<S: Store<K, R>>(&mut self, s: &mut S)
    where
        S::Error: Debug,
    {
        let deadline = UnixTime::new(self.now.secs() + 1);
        let e = self.build(|b, c| {
            b.create(c.k(0), c.r(0), Some(deadline))
                .create(c.k(1), c.r(1), Some(deadline));
        });
        assert!(self.apply(s, &e).is_ok(), "expired: create");
        let seen = self.live(s, 1).expect("expired: live before its deadline");
        self.now = deadline;
        assert!(
            self.live(s, 0).is_none(),
            "expired: absent to load at its deadline"
        );
        let stale = self.build(|b, c| {
            b.expect(c.k(1), &seen);
        });
        let conflict = self
            .apply(s, &stale)
            .expect_err("expired: absent to guards");
        assert_eq!(
            self.failures(&conflict),
            vec![(self.k(1), Failure::Missing)]
        );
        let again = self.build(|b, c| {
            b.create(c.k(0), c.r(2), None);
        });
        assert!(
            self.apply(s, &again).is_ok(),
            "expired: Absent holds over an unpurged expired row"
        );
        self.now = UnixTime::new(deadline.secs() - 1);
    }

    fn recreate<S: Store<K, R>>(&mut self, s: &mut S)
    where
        S::Error: Debug,
    {
        let [row] = &self.seed(s, [0]);
        let gone = self.build(|b, c| {
            b.delete(c.k(0), row);
        });
        assert!(self.apply(s, &gone).is_ok(), "recreate: delete");
        self.seed(s, [0]);
        let stale = self.build(|b, c| {
            b.update(c.k(0), row, c.r(1), None);
        });
        let conflict = self
            .apply(s, &stale)
            .expect_err("recreate: a stale version loses");
        assert_eq!(
            self.failures(&conflict),
            vec![(self.k(0), Failure::Changed)]
        );
    }

    fn at_bound<S: Store<K, R>>(&mut self, s: &mut S)
    where
        S::Error: Debug,
    {
        let half = u8::try_from(MAX_EFFECT_SIZE / 2).expect("bound fits u8");
        let e = self.build(|b, c| {
            for n in 0..half {
                b.create(c.k(n), c.r(n), None);
            }
        });
        assert!(
            self.apply(s, &e).is_ok(),
            "at_bound: an effect at the bound applies"
        );
        assert!(
            (0..half).all(|n| self.live(s, n).is_some()),
            "at_bound: every row written"
        );
    }
}
