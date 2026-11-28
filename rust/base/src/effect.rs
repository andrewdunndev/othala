use alloc::collections::BTreeMap;
use alloc::collections::btree_map::Entry;
use alloc::vec::Vec;
use core::fmt;

use sha2::{Digest as _, Sha256};

use crate::{Entropy, Error, ErrorKind, Row, StoreKey, UnixTime, Version};

/// The bound on one effect's guards plus writes.
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

/// Builds an [`Effect`] by value, so a decision is one expression; every write is paired with a guard on its own key.
#[must_use]
#[derive(Debug)]
pub struct Builder<K, R> {
    id: EffectId,
    ops: BTreeMap<K, Op<R>>,
    size: usize,
    fault: Option<ErrorKind>,
}

/// Proof that a store committed one effect; minted only by [`Effect::host_applied`].
#[derive(Debug)]
pub struct Receipt {
    id: EffectId,
}

impl Receipt {
    /// The id of the effect this receipt settles.
    pub const fn effect_id(&self) -> EffectId {
        self.id
    }
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
pub struct Pending<T, K, R> {
    verdict: T,
    effect: Effect<K, R>,
}

impl<K: StoreKey, R> Effect<K, R> {
    /// The general constructor; the id is 16 bytes drawn from `e`.
    pub fn builder(e: &mut impl Entropy) -> Builder<K, R> {
        let mut id = [0; 16];
        e.fill(&mut id);
        Builder {
            id: EffectId(id),
            ops: BTreeMap::new(),
            size: 0,
            fault: None,
        }
    }

    // one guarded write is never empty, never overlaps and is far inside the bound, so it needs no `build`
    fn single(e: &mut impl Entropy, key: K, op: Op<R>) -> Self {
        Self {
            id: Self::builder(e).id,
            ops: BTreeMap::from([(key, op)]),
        }
    }

    /// The one-op effect [`Builder::create`] builds, infallibly.
    pub fn created(e: &mut impl Entropy, key: K, record: R, expiry: Option<UnixTime>) -> Self {
        Self::single(
            e,
            key,
            Op::new(Check::Absent, Some(Write::Put(record, expiry))),
        )
    }

    /// The one-op effect [`Builder::update`] builds, infallibly.
    pub fn updated<S>(
        e: &mut impl Entropy,
        key: K,
        seen: &Row<S>,
        record: R,
        expiry: Option<UnixTime>,
    ) -> Self {
        let check = Check::Unchanged(seen.version());
        Self::single(e, key, Op::new(check, Some(Write::Put(record, expiry))))
    }

    /// The one-op effect [`Builder::consume`] builds, infallibly.
    pub fn consumed(e: &mut impl Entropy, key: K) -> Self {
        Self::single(e, key, Op::new(Check::Consume, Some(Write::Delete)))
    }

    /// The one-op effect [`Builder::delete`] builds, infallibly.
    pub fn deleted<S>(e: &mut impl Entropy, key: K, seen: &Row<S>) -> Self {
        Self::single(
            e,
            key,
            Op::new(Check::Unchanged(seen.version()), Some(Write::Delete)),
        )
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

    /// Every put: key, record and the instant the row stops being live.
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
        if size(&self.ops) + size(&other.ops) > MAX_EFFECT_SIZE {
            return Err(Error::new(ErrorKind::TooLarge));
        }
        let mut ops = self.ops;
        for (k, op) in other.ops {
            match ops.entry(k) {
                Entry::Vacant(slot) => slot.insert(op),
                Entry::Occupied(_) => return Err(Error::new(ErrorKind::Overlap)),
            };
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

    /// The one receipt mint; a lint forbids it in every published crate, and only the `store` member expects it.
    pub const fn host_applied(&self) -> Receipt {
        Receipt { id: self.id }
    }
}

impl<K: StoreKey, R> Builder<K, R> {
    // the first fault latches and later ops are dropped, so an oversize builder never grows
    fn op(mut self, key: K, op: Op<R>) -> Self {
        if self.fault.is_some() {
            return self;
        }
        self.size += op.size();
        if self.size > MAX_EFFECT_SIZE {
            self.fault = Some(ErrorKind::TooLarge);
            return self;
        }
        match self.ops.entry(key) {
            Entry::Vacant(slot) => {
                slot.insert(op);
            }
            Entry::Occupied(_) => self.fault = Some(ErrorKind::Overlap),
        }
        self
    }

    /// `Absent` guard plus a put.
    pub fn create(self, key: K, record: R, expiry: Option<UnixTime>) -> Self {
        self.op(
            key,
            Op::new(Check::Absent, Some(Write::Put(record, expiry))),
        )
    }

    /// `Unchanged` guard at the seen version plus a put; `seen` may be any typed view of the row.
    pub fn update<S>(self, key: K, seen: &Row<S>, record: R, expiry: Option<UnixTime>) -> Self {
        self.op(
            key,
            Op::new(
                Check::Unchanged(seen.version()),
                Some(Write::Put(record, expiry)),
            ),
        )
    }

    /// `Consume` guard: the row must exist and is deleted.
    pub fn consume(self, key: K) -> Self {
        self.op(key, Op::new(Check::Consume, Some(Write::Delete)))
    }

    /// `Unchanged` guard at the seen version plus a delete.
    pub fn delete<S>(self, key: K, seen: &Row<S>) -> Self {
        self.op(
            key,
            Op::new(Check::Unchanged(seen.version()), Some(Write::Delete)),
        )
    }

    /// `Unchanged` guard only.
    pub fn expect<S>(self, key: K, seen: &Row<S>) -> Self {
        self.op(key, Op::new(Check::Unchanged(seen.version()), None))
    }

    /// `Absent` guard only.
    pub fn expect_absent(self, key: K) -> Self {
        self.op(key, Op::new(Check::Absent, None))
    }

    /// The effect, or the first fault: `Overlap` for a key named twice, `TooLarge` past the bound; else `Empty`.
    pub fn build(self) -> Result<Effect<K, R>, Error> {
        let fault = match self.fault {
            Some(kind) => Some(kind),
            None if self.ops.is_empty() => Some(ErrorKind::Empty),
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

impl<T, K, R> fmt::Debug for Pending<T, K, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pending")
            .field("effect", &self.effect.id)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{Builder, Conflict, Effect, Failure, Guard, MAX_EFFECT_SIZE, Pending};
    use crate::{Entropy, ErrorKind, Row, Scope, StoreKey, UnixTime, Version};
    use alloc::format;
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

    fn absent(
        e: &mut Fill,
        keys: impl IntoIterator<Item = u8>,
    ) -> Result<Effect<K, u8>, crate::Error> {
        keys.into_iter()
            .fold(builder(e), |b, n| b.expect_absent(K::G(n)))
            .build()
    }

    #[test]
    fn overlap_in_builder() {
        let b = builder(&mut Fill(0))
            .create(K::G(1), 1, None)
            .expect_absent(K::G(1))
            .create(K::G(2), 2, None);
        assert_eq!(kind(b.build()), Some(ErrorKind::Overlap));
    }

    #[test]
    fn overlap_in_merge() -> Result<(), crate::Error> {
        let e = &mut Fill(0);
        assert_eq!(
            kind(absent(e, [1, 2])?.merge(absent(e, [2, 3])?)),
            Some(ErrorKind::Overlap)
        );
        let merged = absent(e, [1])?.merge(absent(e, [2])?)?;
        assert_eq!(
            merged.guards().collect::<Vec<_>>(),
            [Guard::Absent(&K::G(1)), Guard::Absent(&K::G(2))]
        );
        Ok(())
    }

    #[test]
    fn overlap_in_lift() -> Result<(), crate::Error> {
        let e = &mut Fill(0);
        assert_eq!(
            kind(absent(e, [1, 2])?.lift(|_| K::G(9), |r| r)),
            Some(ErrorKind::Overlap)
        );
        let lifted = absent(e, [1, 2])?.lift(|k| if k == K::G(1) { K::G(7) } else { k }, |r| r)?;
        assert_eq!(
            lifted.guards().map(|g| **g.key()).collect::<Vec<_>>(),
            [K::G(2), K::G(7)]
        );
        Ok(())
    }

    #[test]
    fn scope_changed_in_lift() -> Result<(), crate::Error> {
        let e = &mut Fill(0);
        let to_subject = |k| match k {
            K::G(n) | K::S(n) => K::S(n),
        };
        assert_eq!(
            kind(absent(e, [1])?.lift(to_subject, |r| r)),
            Some(ErrorKind::ScopeChanged)
        );
        let lifted = builder(e)
            .create(K::S(1), 4, Some(UnixTime::new(9)))
            .build()?
            .lift(to_subject, u16::from)?;
        assert_eq!(
            lifted.puts().collect::<Vec<_>>(),
            [(&K::S(1), &4u16, Some(UnixTime::new(9)))]
        );
        Ok(())
    }

    #[test]
    fn single_ops_are_the_builder_ops() -> Result<(), crate::Error> {
        let (seen, e) = (row(4), &mut Fill(0));
        let pairs = [
            (
                Effect::created(e, K::G(1), 1, Some(UnixTime::new(3))),
                builder(&mut Fill(0)).create(K::G(1), 1, Some(UnixTime::new(3))),
            ),
            (
                Effect::updated(e, K::G(2), &seen, 2, None),
                builder(&mut Fill(1)).update(K::G(2), &seen, 2, None),
            ),
            (
                Effect::consumed(e, K::G(3)),
                builder(&mut Fill(2)).consume(K::G(3)),
            ),
            (
                Effect::deleted(e, K::G(4), &seen),
                builder(&mut Fill(3)).delete(K::G(4), &seen),
            ),
        ];
        for (single, built) in pairs {
            assert_eq!(format!("{single:?}"), format!("{:?}", built.build()?));
        }
        Ok(())
    }

    #[test]
    fn empty_build() {
        assert_eq!(kind(builder(&mut Fill(0)).build()), Some(ErrorKind::Empty));
    }

    #[test]
    fn size_bound() -> Result<(), crate::Error> {
        assert_eq!(MAX_EFFECT_SIZE, 128);
        let e = &mut Fill(0);
        let creates = |e: &mut Fill| (0..64).fold(builder(e), |b, n| b.create(K::G(n), n, None));
        assert_eq!(creates(e).build()?.puts().count(), 64);
        let b = creates(e).expect_absent(K::S(0));
        assert_eq!(kind(b.build()), Some(ErrorKind::TooLarge));
        let b =
            builder(e)
                .delete(K::G(0), &row(1))
                .consume(K::G(1))
                .update(K::G(2), &row(1), 0, None);
        let b = (3..125).fold(b, |b, n| b.expect(K::G(n), &row(1)));
        let built = b.build()?;
        assert_eq!((built.puts().count(), built.deletes().count()), (1, 2));
        assert_eq!(built.guards().count(), 125);
        assert_eq!(
            absent(e, 0..64)?
                .merge(absent(e, 64..128)?)?
                .guards()
                .count(),
            128
        );
        assert_eq!(
            kind(absent(e, 0..64)?.merge(absent(e, 64..=128)?)),
            Some(ErrorKind::TooLarge)
        );
        assert_eq!(
            kind(absent(e, 0..64)?.merge(absent(e, 0..65)?)),
            Some(ErrorKind::TooLarge)
        );
        Ok(())
    }

    #[test]
    fn oversize_builder_stops_growing() {
        let b = (0..=255).fold(builder(&mut Fill(0)), |b, n| {
            b.expect_absent(K::G(n)).expect_absent(K::S(n))
        });
        assert_eq!((b.ops.len(), b.size), (128, 129));
        assert_eq!(kind(b.build()), Some(ErrorKind::TooLarge));
        let b = builder(&mut Fill(0))
            .expect_absent(K::G(0))
            .expect_absent(K::G(0));
        let b = (1..=255).fold(b, |b, n| b.expect_absent(K::G(n)));
        assert_eq!(b.ops.len(), 1);
        assert_eq!(kind(b.build()), Some(ErrorKind::Overlap));
    }

    #[test]
    fn domain_of_keys() -> Result<(), crate::Error> {
        let e = &mut Fill(0);
        let two = absent(e, [1, 2])?;
        assert_eq!(two.domain(|_| 'a')?, 'a');
        assert_eq!(kind(two.domain(|k| *k)), Some(ErrorKind::SpansDomains));
        assert_eq!(absent(e, [5])?.domain(|k| *k)?, K::G(5));
        let third_differs = absent(e, [1, 2, 3])?.domain(|k| u8::from(*k == K::G(3)));
        assert_eq!(kind(third_differs), Some(ErrorKind::SpansDomains));
        Ok(())
    }

    #[test]
    fn settle_by_receipt() -> Result<(), crate::Error> {
        let e = &mut Fill(0);
        let mine = Pending::new(7, absent(e, [1])?);
        let other = absent(e, [1])?;
        assert_eq!(other.host_applied().effect_id(), other.id());
        assert_ne!(other.host_applied().effect_id(), mine.effect().id());
        assert_eq!(
            kind(mine.settle(other.host_applied())),
            Some(ErrorKind::WrongReceipt)
        );
        let mine = Pending::new(7, absent(e, [1])?);
        let receipt = mine.effect().host_applied();
        assert_eq!(mine.settle(receipt)?, 7);
        Ok(())
    }

    #[test]
    fn ids() -> Result<(), crate::Error> {
        let e = &mut Fill(4);
        let a = absent(e, [1])?;
        assert_eq!(a.id().as_bytes(), &[5; 16]);
        let b = absent(e, [2])?;
        let want = Sha256::new()
            .chain_update([5; 16])
            .chain_update([6; 16])
            .finalize();
        let merged = a.merge(b)?;
        assert_eq!(merged.id().as_bytes()[..], want[..16]);
        let id = merged.id();
        assert_eq!(merged.lift(|k| k, |r| r)?.id(), id);
        Ok(())
    }

    #[test]
    fn check_names_each_failure() -> Result<(), crate::Error> {
        let effect = builder(&mut Fill(0))
            .consume(K::G(1))
            .update(K::G(2), &row(1), 0, None)
            .expect_absent(K::G(3))
            .expect(K::G(4), &row(1))
            .delete(K::G(5), &row(1))
            .create(K::G(6), 0, None)
            .build()?;
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
        Ok(())
    }

    #[test]
    fn views() -> Result<(), crate::Error> {
        let e = builder(&mut Fill(0))
            .create(K::G(1), 10, Some(UnixTime::new(3)))
            .update(K::G(2), &row(4), 20, Some(UnixTime::new(8)))
            .consume(K::G(3))
            .delete(K::G(4), &row(5))
            .expect(K::G(5), &row(6))
            .expect_absent(K::G(6))
            .build()?;
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
                (&K::G(2), &20, Some(UnixTime::new(8)))
            ]
        );
        assert_eq!(e.deletes().collect::<Vec<_>>(), [&K::G(3), &K::G(4)]);
        Ok(())
    }

    #[test]
    fn seen_rows_of_any_type() -> Result<(), crate::Error> {
        let typed = Row::new("credential", Version::new(3));
        let e = builder(&mut Fill(0))
            .update(K::G(1), &typed, 1, None)
            .delete(K::G(2), &typed)
            .expect(K::G(3), &typed)
            .build()?;
        let v = Version::new(3);
        assert_eq!(
            e.guards().collect::<Vec<_>>(),
            [
                Guard::Unchanged(&K::G(1), v),
                Guard::Unchanged(&K::G(2), v),
                Guard::Unchanged(&K::G(3), v),
            ]
        );
        Ok(())
    }

    #[test]
    fn pending_combinators() -> Result<(), crate::Error> {
        let e = &mut Fill(0);
        let a = Pending::new(1u8, absent(e, [1])?);
        let b = Pending::new('b', absent(e, [2])?);
        let lifted = a.join(b)?.lift(|k| k, |r| r)?;
        assert_eq!(lifted.effect().guards().count(), 2);
        let receipt = lifted.effect().host_applied();
        assert_eq!(lifted.settle(receipt)?, (1, 'b'));
        let clash = Pending::new(1u8, absent(e, [1])?).join(Pending::new(2u8, absent(e, [1])?));
        assert_eq!(kind(clash), Some(ErrorKind::Overlap));
        assert_eq!(
            kind(Pending::new(1u8, absent(e, [1, 2])?).lift(|_| K::G(0), |r| r)),
            Some(ErrorKind::Overlap)
        );
        Ok(())
    }

    #[test]
    fn pending_debug_shows_only_the_effect_id() -> Result<(), crate::Error> {
        let p = Pending::new("session granted", absent(&mut Fill(2), [1])?);
        assert_eq!(
            format!("{p:?}"),
            format!("Pending {{ effect: {:?}, .. }}", p.effect().id())
        );
        Ok(())
    }
}
