use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::{Entropy, Error, ErrorKind, Row, StoreKey, UnixTime, Version};

/// The bound on one effect's guards plus writes (section 5 rule 7).
pub const MAX_EFFECT_SIZE: usize = 128;

/// An effect's identity: 16 bytes of entropy, or the digest of two merged ids.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EffectId([u8; 16]);

impl EffectId {
    /// The id bytes, for a store's applied-id record.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        todo!()
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
        todo!()
    }
}

#[derive(Debug)]
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
        todo!()
    }

    /// The effect's identity; a store records it to make re-applies idempotent.
    pub const fn id(&self) -> EffectId {
        todo!()
    }

    /// Every guard, one per key.
    pub fn guards(&self) -> impl Iterator<Item = Guard<&K>> {
        todo!();
        core::iter::empty()
    }

    /// Every put: key, record and the store's garbage-collection bound.
    pub fn puts(&self) -> impl Iterator<Item = (&K, &R, Option<UnixTime>)> {
        todo!();
        core::iter::empty()
    }

    /// Every key whose row is deleted, consumed ones included.
    pub fn deletes(&self) -> impl Iterator<Item = &K> {
        todo!();
        core::iter::empty()
    }

    /// Evaluates every guard against `live` (a key's live version, `None` if absent) and names each failure.
    pub fn check(&self, live: impl FnMut(&K) -> Option<Version>) -> Result<(), Conflict<K>> {
        todo!()
    }

    /// Re-keys for a consumer under the same id; `Overlap` if two keys collide, `ScopeChanged` if a scope moves.
    pub fn lift<K2: StoreKey, R2>(
        self,
        key: impl Fn(K) -> K2,
        record: impl Fn(R) -> R2,
    ) -> Result<Effect<K2, R2>, Error> {
        todo!()
    }

    /// One effect from two: `Overlap` if a key is in both, `TooLarge` past the bound; the id is the digest of both ids.
    pub fn merge(self, other: Self) -> Result<Self, Error> {
        todo!()
    }

    /// The one transaction domain every key maps to, or `SpansDomains`.
    pub fn domain<D: Eq>(&self, of: impl Fn(&K) -> D) -> Result<D, Error> {
        todo!()
    }

    /// The one receipt mint; lint-confined to store modules.
    pub fn host_applied(&self) -> Receipt {
        todo!()
    }
}

impl<K: StoreKey, R> Builder<K, R> {
    /// `Absent` guard plus a put.
    pub fn create(&mut self, key: K, record: R, expiry: Option<UnixTime>) -> &mut Self {
        todo!()
    }

    /// `Unchanged` guard at the seen version plus a put.
    pub fn update(
        &mut self,
        key: K,
        seen: &Row<R>,
        record: R,
        expiry: Option<UnixTime>,
    ) -> &mut Self {
        todo!()
    }

    /// `Consume` guard: the row must exist and is deleted.
    pub fn consume(&mut self, key: K) -> &mut Self {
        todo!()
    }

    /// `Unchanged` guard at the seen version plus a delete.
    pub fn delete(&mut self, key: K, seen: &Row<R>) -> &mut Self {
        todo!()
    }

    /// `Unchanged` guard only.
    pub fn expect(&mut self, key: K, seen: &Row<R>) -> &mut Self {
        todo!()
    }

    /// `Absent` guard only.
    pub fn expect_absent(&mut self, key: K) -> &mut Self {
        todo!()
    }

    /// The effect, or `Overlap` for a key named twice, `Empty`, or `TooLarge`.
    pub fn build(self) -> Result<Effect<K, R>, Error> {
        todo!()
    }
}

impl<K> Conflict<K> {
    /// A conflict naming one failed guard, for a store's own constraint failure.
    pub fn new(key: K, failure: Failure) -> Self {
        todo!()
    }

    /// Names one more failed guard.
    pub fn push(&mut self, key: K, failure: Failure) -> &mut Self {
        todo!()
    }

    /// Each failed guard.
    pub fn failures(&self) -> &[(K, Failure)] {
        todo!()
    }
}

impl<T, K: StoreKey, R> Pending<T, K, R> {
    /// Holds `verdict` until `effect` is applied.
    pub const fn new(verdict: T, effect: Effect<K, R>) -> Self {
        todo!()
    }

    /// The effect to apply.
    pub const fn effect(&self) -> &Effect<K, R> {
        todo!()
    }

    /// The verdict, against its own effect's receipt; `WrongReceipt` otherwise, and the verdict is gone.
    pub fn settle(self, receipt: Receipt) -> Result<T, Error> {
        todo!()
    }

    /// Maps the verdict; the effect is unchanged.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Pending<U, K, R> {
        todo!()
    }

    /// As [`Effect::lift`].
    pub fn lift<K2: StoreKey, R2>(
        self,
        key: impl Fn(K) -> K2,
        record: impl Fn(R) -> R2,
    ) -> Result<Pending<T, K2, R2>, Error> {
        todo!()
    }

    /// As [`Effect::merge`]: one effect, one receipt.
    pub fn join<U>(self, other: Pending<U, K, R>) -> Result<Pending<(T, U), K, R>, Error> {
        todo!()
    }
}
