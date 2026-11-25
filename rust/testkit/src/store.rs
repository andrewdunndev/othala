use std::collections::{BTreeMap, BTreeSet};

use base::{Conflict, Effect, EffectId, Receipt, Row, Rows, Store, StoreKey, UnixTime, Version};

/// Why the reference store answered `Error`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Injected: the effect committed and its result was lost.
    Lost,
    /// A put on a key the same effect does not guard; never reachable through the builder.
    Unguarded,
}

#[derive(Clone, Debug)]
struct Stored<R> {
    record: R,
    version: Version,
    expiry: Option<UnixTime>,
}

impl<R> Stored<R> {
    fn live(&self, now: UnixTime) -> bool {
        self.expiry.is_none_or(|t| now < t)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AppliedIds {
    Recorded,
    Forgotten,
}

/// The in-memory reference `Store`: strict, single-threaded, and recording every key loaded.
#[derive(Clone, Debug)]
pub struct MemStore<K, R> {
    rows: BTreeMap<K, Stored<R>>,
    applied: BTreeSet<EffectId>,
    counter: u64,
    reads: BTreeSet<K>,
    lose: u32,
    ids: AppliedIds,
}

impl<K: StoreKey, R: Clone> MemStore<K, R> {
    /// An empty store.
    pub const fn new() -> Self {
        Self {
            rows: BTreeMap::new(),
            applied: BTreeSet::new(),
            counter: 0,
            reads: BTreeSet::new(),
            lose: 0,
            ids: AppliedIds::Recorded,
        }
    }

    /// The next apply commits and then answers `Fault::Lost`.
    pub fn lose_next_result(&mut self) -> &mut Self {
        self.lose += 1;
        self
    }

    /// Probes only: stop recording applied ids, so a re-apply is decided afresh (a broken store).
    pub fn forget_applied_ids(&mut self) -> &mut Self {
        self.ids = AppliedIds::Forgotten;
        self
    }

    /// The keys loaded since the last call.
    pub fn take_reads(&mut self) -> BTreeSet<K> {
        std::mem::take(&mut self.reads)
    }

    /// Every live row's record.
    pub fn contents(&self, now: UnixTime) -> BTreeMap<K, R> {
        self.rows
            .iter()
            .filter(|(_, s)| s.live(now))
            .map(|(k, s)| (k.clone(), s.record.clone()))
            .collect()
    }

    fn version(&self, key: &K, now: UnixTime) -> Option<Version> {
        self.rows
            .get(key)
            .filter(|s| s.live(now))
            .map(|s| s.version)
    }
}

impl<K: StoreKey, R: Clone> Default for MemStore<K, R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: StoreKey, R: Clone> Store<K, R> for MemStore<K, R> {
    type Error = Fault;

    fn load(&mut self, keys: &[K], now: UnixTime) -> Result<Rows<K, R>, Fault> {
        let mut rows = Rows::new();
        for key in keys {
            self.reads.insert(key.clone());
            let row = self
                .rows
                .get(key)
                .filter(|s| s.live(now))
                .map(|s| Row::new(s.record.clone(), s.version));
            rows.insert(key.clone(), row);
        }
        Ok(rows)
    }

    fn apply(
        &mut self,
        effect: &Effect<K, R>,
        now: UnixTime,
    ) -> Result<Result<Receipt, Conflict<K>>, Fault> {
        if self.applied.contains(&effect.id()) {
            return Ok(Ok(mint(effect)));
        }
        let guarded: BTreeSet<&K> = effect.guards().map(|g| *g.key()).collect();
        if effect.puts().any(|(k, _, _)| !guarded.contains(k))
            || effect.deletes().any(|k| !guarded.contains(k))
        {
            return Err(Fault::Unguarded);
        }
        if let Err(conflict) = effect.check(|k| self.version(k, now)) {
            return Ok(Err(conflict));
        }
        for key in effect.deletes() {
            self.rows.remove(key);
        }
        for (key, record, expiry) in effect.puts() {
            self.counter += 1;
            let stored = Stored {
                record: record.clone(),
                version: Version::new(self.counter),
                expiry,
            };
            self.rows.insert(key.clone(), stored);
        }
        if self.ids == AppliedIds::Recorded {
            self.applied.insert(effect.id());
        }
        if self.lose > 0 {
            self.lose -= 1;
            return Err(Fault::Lost);
        }
        Ok(Ok(mint(effect)))
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "the reference store's one receipt mint"
)]
fn mint<K: StoreKey, R>(effect: &Effect<K, R>) -> Receipt {
    effect.host_applied()
}

#[cfg(test)]
mod tests {
    use base::{Effect, Pending, Scope, Store, StoreKey, UnixTime};

    use super::{Fault, MemStore};
    use crate::seeded;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct K(u8);

    impl StoreKey for K {
        fn scope(&self) -> Scope {
            Scope::Global
        }
    }

    const NOW: UnixTime = UnixTime::new(1);

    fn create(seed: u64, k: u8) -> Effect<K, u8> {
        Effect::builder(&mut seeded(seed))
            .create(K(k), k, None)
            .build()
            .expect("one create builds")
    }

    #[test]
    fn a_lost_result_commits_and_a_reapply_settles() {
        let mut s = MemStore::<K, u8>::new();
        s.lose_next_result().lose_next_result();
        let a = Pending::new('a', create(1, 1));
        let b = create(2, 2);
        assert_eq!(s.apply(a.effect(), NOW).err(), Some(Fault::Lost));
        assert_eq!(s.apply(&b, NOW).err(), Some(Fault::Lost));
        assert_eq!(s.contents(NOW).len(), 2, "both lost results committed");
        let receipt = s
            .apply(a.effect(), NOW)
            .expect("third apply known")
            .expect("re-apply is Ok");
        assert_eq!(a.settle(receipt).ok(), Some('a'));
        assert!(s.apply(&create(3, 3), NOW).expect("losses spent").is_ok());
        assert_eq!(s.contents(NOW).len(), 3);
    }
}
