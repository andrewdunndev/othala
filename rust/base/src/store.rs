use alloc::collections::BTreeMap;

use crate::{Conflict, Effect, Receipt, UnixTime};

/// How far a key's uniqueness reaches.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    /// Unique across the whole store; a consumer never qualifies it.
    Global,
    /// Unique within one subject; a consumer qualifies it with the subject.
    Subject,
}

/// A key a protocol crate emits in its effects.
pub trait StoreKey: Ord + Clone {
    /// The key's uniqueness scope.
    fn scope(&self) -> Scope;
}

/// A row version; a store never repeats one for a key, across deletes too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(u64);

impl Version {
    /// A version as the store recorded it.
    pub const fn new(v: u64) -> Self {
        todo!()
    }

    /// The stored value.
    pub const fn get(self) -> u64 {
        todo!()
    }
}

/// A record as a store hands it in, with the version it was read at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row<R> {
    record: R,
    version: Version,
}

impl<R> Row<R> {
    /// A row read from a store.
    pub const fn new(record: R, version: Version) -> Self {
        todo!()
    }

    /// The decoded record.
    pub const fn record(&self) -> &R {
        todo!()
    }

    /// The version the row was read at.
    pub const fn version(&self) -> Version {
        todo!()
    }

    /// The record, giving up the row.
    pub fn into_record(self) -> R {
        todo!()
    }
}

/// What a row set holds for one loaded key.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot<'a, R> {
    /// The row exists and decoded.
    Row(&'a Row<R>),
    /// No live row: never stored, deleted or expired.
    Absent,
    /// The row exists but did not decode; never to be read as absent.
    Corrupt,
}

#[derive(Debug)]
enum Stored<R> {
    Row(Row<R>),
    Absent,
    Corrupt,
}

/// The one row-set shape, for [`Store::load`] and every protocol's row reply.
#[derive(Debug)]
pub struct Rows<K, R> {
    slots: BTreeMap<K, Stored<R>>,
}

impl<K: Ord, R> Rows<K, R> {
    /// An empty row set.
    pub const fn new() -> Self {
        todo!()
    }

    /// Records a loaded key: `Some` row, or `None` for absent.
    pub fn insert(&mut self, key: K, row: Option<Row<R>>) -> &mut Self {
        todo!()
    }

    /// Records a key whose stored row failed to decode.
    pub fn corrupt(&mut self, key: K) -> &mut Self {
        todo!()
    }

    /// What was loaded for `key`; `None` if it was not loaded.
    pub fn get(&self, key: &K) -> Option<Slot<'_, R>> {
        todo!()
    }
}

impl<K: Ord, R> Default for Rows<K, R> {
    fn default() -> Self {
        Self::new()
    }
}

/// A synchronous store; async hosts apply an [`Effect`] by hand under the same obligation.
pub trait Store<K: StoreKey, R> {
    /// Outcome unknown; a store's own constraint failure is a [`Conflict`], never this.
    type Error;

    /// Loads `keys`; a row past its expiry at `now` is absent.
    fn load(&mut self, keys: &[K], now: UnixTime) -> Result<Rows<K, R>, Self::Error>;

    /// Applies `effect` in one transaction: every guard holds or nothing is applied.
    fn apply(
        &mut self,
        effect: &Effect<K, R>,
        now: UnixTime,
    ) -> Result<Result<Receipt, Conflict<K>>, Self::Error>;
}

/// How many times a host re-applies one effect after an `Error`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retry(u8);

impl Retry {
    /// Allows `attempts` re-applies.
    pub const fn new(attempts: u8) -> Self {
        todo!()
    }

    /// The re-applies allowed.
    pub const fn attempts(self) -> u8 {
        todo!()
    }
}

/// Re-decisions a decider makes after a [`Conflict`] before it answers a server error.
pub const REDECIDE: u8 = 3;
