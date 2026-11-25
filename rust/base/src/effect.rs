use alloc::collections::BTreeMap;
use alloc::collections::btree_map::Entry;
use alloc::vec::Vec;

use sha2::{Digest as _, Sha256};

use crate::{Entropy, Error, ErrorKind, Row, StoreKey, UnixTime, Version};

/// The bound on one effect's guards plus writes (section 5 rule 7).
pub const MAX_EFFECT_SIZE: usize = 128;

/// An effect's identity: 16 bytes of entropy, or the digest of two merged ids.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EffectId([u8; 16]);

impl EffectId {
    /// The id bytes, for a store's applied-id record.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    fn merged(a: Self, b: Self) -> Self {
        let mut id = [0; 16];
        let full = Sha256::new().chain_update(a.0).chain_update(b.0).finalize();
        id.iter_mut().zip(full.iter()).for_each(|(d, s)| *d = *s);
        Self(id)
    }
}

/// A condition a row must meet when the effect applies.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Guard<K> {
    /// The row must exist; it is deleted.
    Consume(K),
    /// The row must exist at this version.
    Unchanged(K, Version),
    /// No live row may exist.
    Absent(K),
}

impl<K> Guard<K> {
    /// The guarded key.
    pub const fn key(&self) -> &K {
        match self {
            Self::Consume(k) | Self::Unchanged(k, _) | Self::Absent(k) => k,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Check {
    Consume,
    Unchanged(Version),
    Absent,
}

#[derive(Debug)]
enum Write<R> {
    Put(R, Option<UnixTime>),
    Delete,
}

#[derive(Debug)]
struct Op<R> {
    check: Check,
    write: Option<Write<R>>,
}

impl<R> Op<R> {
    const fn new(check: Check, write: Option<Write<R>>) -> Self {
        Self { check, write }
    }

    fn size(&self) -> usize {
        1 + usize::from(self.write.is_some())
    }
}

fn size<K, R>(ops: &BTreeMap<K, Op<R>>) -> usize {
    ops.values().map(Op::size).sum()
}

/// Guarded writes a store applies atomically, as data.
#[derive(Debug)]
pub struct Effect<K, R> {
    id: EffectId,
    ops: BTreeMap<K, Op<R>>,
}

/// Builds an [`Effect`]; every write is paired with a guard on its own key.
#[derive(Debug)]
pub struct Builder<K, R> {
    id: EffectId,
    ops: BTreeMap<K, Op<R>>,
    fault: Option<ErrorKind>,
}

/// Proof that a store committed one effect; minted only by [`Effect::host_applied`].
#[derive(Debug)]
pub struct Receipt {
    id: EffectId,
}

/// Why one guard failed.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The row must exist and does not.
    Missing,
    /// The row exists at another version.
    Changed,
    /// The row must be absent and exists.
    Present,
}

/// Every guard that failed; nothing was applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conflict<K> {
    failures: Vec<(K, Failure)>,
}

/// A verdict that is void until settled with its effect's [`Receipt`].
#[must_use]
#[derive(Debug)]
pub struct Pending<T, K, R> {
    verdict: T,
    effect: Effect<K, R>,
}

impl<K: StoreKey, R> Effect<K, R> {
    /// The only constructor; the id is 16 bytes drawn from `e`.
    pub fn builder(e: &mut impl Entropy) -> Builder<K, R> {
        let mut id = [0; 16];
        e.fill(&mut id);
        Builder {
            id: EffectId(id),
            ops: BTreeMap::new(),
            fault: None,
        }
    }

    /// The effect's identity; a store records it to make re-applies idempotent.
    pub const fn id(&self) -> EffectId {
        self.id
    }

    /// Every guard, one per key.
    pub fn guards(&self) -> impl Iterator<Item = Guard<&K>> {
        self.ops.iter().map(|(k, op)| match op.check {
            Check::Consume => Guard::Consume(k),
            Check::Unchanged(v) => Guard::Unchanged(k, v),
            Check::Absent => Guard::Absent(k),
        })
    }

    /// Every put: key, record and the store's garbage-collection bound.
    pub fn puts(&self) -> impl Iterator<Item = (&K, &R, Option<UnixTime>)> {
        self.ops.iter().filter_map(|(k, op)| match &op.write {
            Some(Write::Put(r, expiry)) => Some((k, r, *expiry)),
            _ => None,
        })
    }

    /// Every key whose row is deleted, consumed ones included.
    pub fn deletes(&self) -> impl Iterator<Item = &K> {
        self.ops
            .iter()
            .filter_map(|(k, op)| matches!(op.write, Some(Write::Delete)).then_some(k))
    }

    /// Evaluates every guard against `live` (a key's live version, `None` if absent) and names each failure.
    pub fn check(&self, mut live: impl FnMut(&K) -> Option<Version>) -> Result<(), Conflict<K>> {
        let failures: Vec<_> = self
            .ops
            .iter()
            .filter_map(|(k, op)| {
                let failure = match (op.check, live(k)) {
                    (Check::Consume | Check::Unchanged(_), None) => Failure::Missing,
                    (Check::Unchanged(seen), Some(now)) if seen != now => Failure::Changed,
                    (Check::Absent, Some(_)) => Failure::Present,
                    _ => return None,
                };
                Some((k.clone(), failure))
            })
            .collect();
        if failures.is_empty() {
            Ok(())
        } else {
            Err(Conflict { failures })
        }
    }

    /// Re-keys for a consumer under the same id; `Overlap` if two keys collide, `ScopeChanged` if a scope moves.
    pub fn lift<K2: StoreKey, R2>(
        self,
        key: impl Fn(K) -> K2,
        record: impl Fn(R) -> R2,
    ) -> Result<Effect<K2, R2>, Error> {
        let mut ops = BTreeMap::new();
        for (k, op) in self.ops {
            let scope = k.scope();
            let k2 = key(k);
            if k2.scope() != scope {
                return Err(Error::new(ErrorKind::ScopeChanged));
            }
            let write = op.write.map(|w| match w {
                Write::Put(r, expiry) => Write::Put(record(r), expiry),
                Write::Delete => Write::Delete,
            });
            if ops.insert(k2, Op::new(op.check, write)).is_some() {
                return Err(Error::new(ErrorKind::Overlap));
            }
        }
        Ok(Effect { id: self.id, ops })
    }

    /// One effect from two: `Overlap` if a key is in both, `TooLarge` past the bound; the id is the digest of both ids.
    pub fn merge(self, other: Self) -> Result<Self, Error> {
        let mut ops = self.ops;
        for (k, op) in other.ops {
            match ops.entry(k) {
                Entry::Vacant(slot) => slot.insert(op),
                Entry::Occupied(_) => return Err(Error::new(ErrorKind::Overlap)),
            };
        }
        if size(&ops) > MAX_EFFECT_SIZE {
            return Err(Error::new(ErrorKind::TooLarge));
        }
        Ok(Self {
            id: EffectId::merged(self.id, other.id),
            ops,
        })
    }

    /// The one transaction domain every key maps to, or `SpansDomains`.
    pub fn domain<D: Eq>(&self, of: impl Fn(&K) -> D) -> Result<D, Error> {
        let mut keys = self.ops.keys();
        let first = keys.next().map(&of).ok_or(Error::new(ErrorKind::Empty))?;
        if keys.all(|k| of(k) == first) {
            Ok(first)
        } else {
            Err(Error::new(ErrorKind::SpansDomains))
        }
    }

    /// The one receipt mint; lint-confined to store modules.
    pub const fn host_applied(&self) -> Receipt {
        Receipt { id: self.id }
    }
}

impl<K: StoreKey, R> Builder<K, R> {
    fn op(&mut self, key: K, op: Op<R>) -> &mut Self {
        match self.ops.entry(key) {
            Entry::Vacant(slot) => {
                slot.insert(op);
            }
            Entry::Occupied(_) => self.fault = Some(ErrorKind::Overlap),
        }
        self
    }

    /// `Absent` guard plus a put.
    pub fn create(&mut self, key: K, record: R, expiry: Option<UnixTime>) -> &mut Self {
        self.op(
            key,
            Op::new(Check::Absent, Some(Write::Put(record, expiry))),
        )
    }

    /// `Unchanged` guard at the seen version plus a put.
    pub fn update(
        &mut self,
        key: K,
        seen: &Row<R>,
        record: R,
        expiry: Option<UnixTime>,
    ) -> &mut Self {
        self.op(
            key,
            Op::new(
                Check::Unchanged(seen.version()),
                Some(Write::Put(record, expiry)),
            ),
        )
    }

    /// `Consume` guard: the row must exist and is deleted.
    pub fn consume(&mut self, key: K) -> &mut Self {
        self.op(key, Op::new(Check::Consume, Some(Write::Delete)))
    }

    /// `Unchanged` guard at the seen version plus a delete.
    pub fn delete(&mut self, key: K, seen: &Row<R>) -> &mut Self {
        self.op(
            key,
            Op::new(Check::Unchanged(seen.version()), Some(Write::Delete)),
        )
    }

    /// `Unchanged` guard only.
    pub fn expect(&mut self, key: K, seen: &Row<R>) -> &mut Self {
        self.op(key, Op::new(Check::Unchanged(seen.version()), None))
    }

    /// `Absent` guard only.
    pub fn expect_absent(&mut self, key: K) -> &mut Self {
        self.op(key, Op::new(Check::Absent, None))
    }

    /// The effect, or `Overlap` for a key named twice, `Empty`, or `TooLarge`.
    pub fn build(self) -> Result<Effect<K, R>, Error> {
        let fault = match self.fault {
            Some(kind) => Some(kind),
            None if self.ops.is_empty() => Some(ErrorKind::Empty),
            None if size(&self.ops) > MAX_EFFECT_SIZE => Some(ErrorKind::TooLarge),
            None => None,
        };
        match fault {
            Some(kind) => Err(Error::new(kind)),
            None => Ok(Effect {
                id: self.id,
                ops: self.ops,
            }),
        }
    }
}

impl<K> Conflict<K> {
    /// A conflict naming one failed guard, for a store's own constraint failure.
    pub fn new(key: K, failure: Failure) -> Self {
        Self {
            failures: alloc::vec![(key, failure)],
        }
    }

    /// Names one more failed guard.
    pub fn push(&mut self, key: K, failure: Failure) -> &mut Self {
        self.failures.push((key, failure));
        self
    }

    /// Each failed guard.
    pub fn failures(&self) -> &[(K, Failure)] {
        &self.failures
    }
}

impl<T, K: StoreKey, R> Pending<T, K, R> {
    /// Holds `verdict` until `effect` is applied.
    pub const fn new(verdict: T, effect: Effect<K, R>) -> Self {
        Self { verdict, effect }
    }

    /// The effect to apply.
    pub const fn effect(&self) -> &Effect<K, R> {
        &self.effect
    }

    /// The verdict, against its own effect's receipt; `WrongReceipt` otherwise, and the verdict is gone.
    pub fn settle(self, receipt: Receipt) -> Result<T, Error> {
        if receipt.id == self.effect.id {
            Ok(self.verdict)
        } else {
            Err(Error::new(ErrorKind::WrongReceipt))
        }
    }

    /// Maps the verdict; the effect is unchanged.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Pending<U, K, R> {
        Pending {
            verdict: f(self.verdict),
            effect: self.effect,
        }
    }

    /// As [`Effect::lift`].
    pub fn lift<K2: StoreKey, R2>(
        self,
        key: impl Fn(K) -> K2,
        record: impl Fn(R) -> R2,
    ) -> Result<Pending<T, K2, R2>, Error> {
        Ok(Pending {
            verdict: self.verdict,
            effect: self.effect.lift(key, record)?,
        })
    }

    /// As [`Effect::merge`]: one effect, one receipt.
    pub fn join<U>(self, other: Pending<U, K, R>) -> Result<Pending<(T, U), K, R>, Error> {
        Ok(Pending {
            verdict: (self.verdict, other.verdict),
            effect: self.effect.merge(other.effect)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Builder, Conflict, Effect, Failure, Guard, MAX_EFFECT_SIZE, Pending};
    use crate::{Entropy, ErrorKind, Row, Scope, StoreKey, UnixTime, Version};
    use alloc::vec::Vec;
    use sha2::{Digest as _, Sha256};

    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    enum K {
        G(u8),
        S(u8),
    }

    impl StoreKey for K {
        fn scope(&self) -> Scope {
            match self {
                K::G(_) => Scope::Global,
                K::S(_) => Scope::Subject,
            }
        }
    }

    struct Fill(u8);

    impl Entropy for Fill {
        fn fill(&mut self, out: &mut [u8]) {
            self.0 += 1;
            out.fill(self.0);
        }
    }

    fn builder(e: &mut Fill) -> Builder<K, u8> {
        Effect::builder(e)
    }

    fn row(v: u64) -> Row<u8> {
        Row::new(0, Version::new(v))
    }

    fn kind<T>(r: Result<T, crate::Error>) -> Option<ErrorKind> {
        r.err().map(|e| e.kind())
    }

    fn absent(e: &mut Fill, keys: impl IntoIterator<Item = u8>) -> Effect<K, u8> {
        let mut b = builder(e);
        keys.into_iter().for_each(|n| {
            b.expect_absent(K::G(n));
        });
        b.build().unwrap()
    }

    #[test]
    fn overlap_in_builder() {
        let mut b = builder(&mut Fill(0));
        b.create(K::G(1), 1, None)
            .expect_absent(K::G(1))
            .create(K::G(2), 2, None);
        assert_eq!(kind(b.build()), Some(ErrorKind::Overlap));
    }

    #[test]
    fn overlap_in_merge() {
        let e = &mut Fill(0);
        assert_eq!(
            kind(absent(e, [1, 2]).merge(absent(e, [2, 3]))),
            Some(ErrorKind::Overlap)
        );
        let merged = absent(e, [1]).merge(absent(e, [2])).unwrap();
        assert_eq!(
            merged.guards().collect::<Vec<_>>(),
            [Guard::Absent(&K::G(1)), Guard::Absent(&K::G(2))]
        );
    }

    #[test]
    fn overlap_in_lift() {
        let e = &mut Fill(0);
        assert_eq!(
            kind(absent(e, [1, 2]).lift(|_| K::G(9), |r| r)),
            Some(ErrorKind::Overlap)
        );
        let lifted = absent(e, [1, 2])
            .lift(|k| if k == K::G(1) { K::G(7) } else { k }, |r| r)
            .unwrap();
        assert_eq!(
            lifted.guards().map(|g| **g.key()).collect::<Vec<_>>(),
            [K::G(2), K::G(7)]
        );
    }

    #[test]
    fn scope_changed_in_lift() {
        let e = &mut Fill(0);
        let to_subject = |k| match k {
            K::G(n) | K::S(n) => K::S(n),
        };
        assert_eq!(
            kind(absent(e, [1]).lift(to_subject, |r| r)),
            Some(ErrorKind::ScopeChanged)
        );
        let mut b = builder(e);
        b.create(K::S(1), 4, Some(UnixTime::new(9)));
        let lifted = b.build().unwrap().lift(to_subject, u16::from).unwrap();
        assert_eq!(
            lifted.puts().collect::<Vec<_>>(),
            [(&K::S(1), &4u16, Some(UnixTime::new(9)))]
        );
    }

    #[test]
    fn empty_build() {
        assert_eq!(kind(builder(&mut Fill(0)).build()), Some(ErrorKind::Empty));
    }

    #[test]
    fn size_bound() {
        let e = &mut Fill(0);
        let half = u8::try_from(MAX_EFFECT_SIZE / 2).unwrap();
        let mut b = builder(e);
        (0..half).for_each(|n| {
            b.create(K::G(n), n, None);
        });
        assert!(b.build().is_ok());
        let mut b = builder(e);
        (0..half).for_each(|n| {
            b.create(K::G(n), n, None);
        });
        b.expect_absent(K::S(0));
        assert_eq!(kind(b.build()), Some(ErrorKind::TooLarge));
        let mut b = builder(e);
        b.delete(K::G(0), &row(1))
            .consume(K::G(1))
            .update(K::G(2), &row(1), 0, None);
        (3..u8::try_from(MAX_EFFECT_SIZE - 3).unwrap()).for_each(|n| {
            b.expect(K::G(n), &row(1));
        });
        assert!(b.build().is_ok());
        let full = u8::try_from(MAX_EFFECT_SIZE).unwrap();
        assert!(absent(e, 0..half).merge(absent(e, half..full)).is_ok());
        assert_eq!(
            kind(absent(e, 0..half).merge(absent(e, half..=full))),
            Some(ErrorKind::TooLarge)
        );
    }

    #[test]
    fn domain_of_keys() {
        let e = &mut Fill(0);
        let two = absent(e, [1, 2]);
        assert_eq!(two.domain(|_| 'a').unwrap(), 'a');
        assert_eq!(kind(two.domain(|k| *k)), Some(ErrorKind::SpansDomains));
        assert_eq!(absent(e, [5]).domain(|k| *k).unwrap(), K::G(5));
    }

    #[test]
    fn settle_by_receipt() {
        let e = &mut Fill(0);
        let mine = Pending::new(7, absent(e, [1]));
        let other = absent(e, [1]);
        assert_eq!(
            kind(mine.settle(other.host_applied())),
            Some(ErrorKind::WrongReceipt)
        );
        let mine = Pending::new(7, absent(e, [1]));
        let receipt = mine.effect().host_applied();
        assert_eq!(mine.settle(receipt).unwrap(), 7);
    }

    #[test]
    fn ids() {
        let e = &mut Fill(4);
        let a = absent(e, [1]);
        assert_eq!(a.id().as_bytes(), &[5; 16]);
        let b = absent(e, [2]);
        let want = Sha256::new()
            .chain_update([5; 16])
            .chain_update([6; 16])
            .finalize();
        let merged = a.merge(b).unwrap();
        assert_eq!(merged.id().as_bytes()[..], want[..16]);
        let id = merged.id();
        assert_eq!(merged.lift(|k| k, |r| r).unwrap().id(), id);
    }

    #[test]
    fn check_names_each_failure() {
        let mut b = builder(&mut Fill(0));
        b.consume(K::G(1))
            .update(K::G(2), &row(1), 0, None)
            .expect_absent(K::G(3))
            .expect(K::G(4), &row(1))
            .delete(K::G(5), &row(1))
            .create(K::G(6), 0, None);
        let effect = b.build().unwrap();
        let held = |k: &K| match k {
            K::G(3) | K::G(6) => None,
            _ => Some(Version::new(1)),
        };
        assert_eq!(effect.check(held), Ok(()));
        let broken = |k: &K| match k {
            K::G(1) | K::G(5) => None,
            K::G(2) => Some(Version::new(2)),
            K::G(3) => Some(Version::new(0)),
            K::G(4) => Some(Version::new(1)),
            _ => None,
        };
        let mut want = Conflict::new(K::G(1), Failure::Missing);
        want.push(K::G(2), Failure::Changed)
            .push(K::G(3), Failure::Present)
            .push(K::G(5), Failure::Missing);
        assert_eq!(effect.check(broken), Err(want.clone()));
        assert_eq!(want.failures().len(), 4);
    }

    #[test]
    fn views() {
        let mut b = builder(&mut Fill(0));
        b.create(K::G(1), 10, Some(UnixTime::new(3)))
            .update(K::G(2), &row(4), 20, None)
            .consume(K::G(3))
            .delete(K::G(4), &row(5))
            .expect(K::G(5), &row(6))
            .expect_absent(K::G(6));
        let e = b.build().unwrap();
        let v = Version::new;
        assert_eq!(
            e.guards().collect::<Vec<_>>(),
            [
                Guard::Absent(&K::G(1)),
                Guard::Unchanged(&K::G(2), v(4)),
                Guard::Consume(&K::G(3)),
                Guard::Unchanged(&K::G(4), v(5)),
                Guard::Unchanged(&K::G(5), v(6)),
                Guard::Absent(&K::G(6)),
            ]
        );
        assert_eq!(
            e.puts().collect::<Vec<_>>(),
            [
                (&K::G(1), &10, Some(UnixTime::new(3))),
                (&K::G(2), &20, None)
            ]
        );
        assert_eq!(e.deletes().collect::<Vec<_>>(), [&K::G(3), &K::G(4)]);
    }

    #[test]
    fn pending_combinators() {
        let e = &mut Fill(0);
        let a = Pending::new(1u8, absent(e, [1]));
        let b = Pending::new('b', absent(e, [2]));
        let joined = a.map(|n| n + 1).join(b).unwrap();
        let lifted = joined.lift(|k| k, |r| r).unwrap();
        assert_eq!(lifted.effect().guards().count(), 2);
        let receipt = lifted.effect().host_applied();
        assert_eq!(lifted.settle(receipt).unwrap(), (2, 'b'));
        let clash = Pending::new(1u8, absent(e, [1])).join(Pending::new(2u8, absent(e, [1])));
        assert_eq!(kind(clash), Some(ErrorKind::Overlap));
        assert_eq!(
            kind(Pending::new(1u8, absent(e, [1, 2])).lift(|_| K::G(0), |r| r)),
            Some(ErrorKind::Overlap)
        );
    }
}
