//! The reference store against the store-effect obligation, and a table of lying stores, each caught by its own case.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use base::{
    Conflict, Effect, EffectId, Guard, Receipt, Row, Rows, Scope, Store, StoreKey, UnixTime,
    Version,
};
use store::{Fault, MemStore};
use testkit::{RACERS, store_conformance, store_conformance_shared};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct K(u8);

impl StoreKey for K {
    fn scope(&self) -> Scope {
        Scope::Global
    }
}

#[test]
fn memstore() {
    store_conformance(MemStore::<K, u16>::new, K, u16::from);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lie {
    Honest,
    SkipWrites,
    ConflictAsError,
    EagerPuts,
    EagerDeletes,
    StopAtFirstFailure,
    ExpectBumps,
    TableVersion,
    ConsumeSweepsSibling,
    UpdateRewritesSibling,
    NoAppliedId,
    IdAfterGuards,
    RecordsConflictedId,
    UniqueAsError,
    LiveAtDeadline,
    GuardsIgnoreExpiry,
    ConsumeIgnoresExpiry,
    WritesIgnoreExpiry,
    UpdateDropsExpiry,
    RecreateAfterExpiryRepeats,
    VersionPerKey,
    SmallBound,
    SmallDeleteBound,
    IdOnly,
    WrongReceipt,
}

const CAUGHT_IN: [(Lie, &str); 24] = [
    (Lie::SkipWrites, "atomic: "),
    (Lie::ConflictAsError, "atomic: "),
    (Lie::EagerPuts, "atomic: "),
    (Lie::EagerDeletes, "atomic: "),
    (Lie::StopAtFirstFailure, "fails_after_write: "),
    (Lie::ExpectBumps, "expect_shared: "),
    (Lie::TableVersion, "disjoint: "),
    (Lie::ConsumeSweepsSibling, "isolated: "),
    (Lie::UpdateRewritesSibling, "isolated: "),
    (Lie::NoAppliedId, "reapply: "),
    (Lie::IdAfterGuards, "reapply: "),
    (Lie::RecordsConflictedId, "conflict_not_applied: "),
    (Lie::UniqueAsError, "duplicate_create: "),
    (Lie::LiveAtDeadline, "expired: "),
    (Lie::GuardsIgnoreExpiry, "expired: "),
    (Lie::ConsumeIgnoresExpiry, "expired: "),
    (Lie::WritesIgnoreExpiry, "expired: "),
    (Lie::UpdateDropsExpiry, "expired: "),
    (Lie::RecreateAfterExpiryRepeats, "expired: "),
    (Lie::VersionPerKey, "recreate: "),
    (Lie::SmallBound, "at_bound: "),
    (Lie::SmallDeleteBound, "at_bound: "),
    (Lie::IdOnly, "reused_id: "),
    (Lie::WrongReceipt, "atomic: "),
];

#[test]
fn the_honest_liar_passes() {
    store_conformance(|| Liar::new(Lie::Honest), K, u16::from);
}

#[test]
fn each_lie_is_caught_by_its_case() {
    for (lie, case) in CAUGHT_IN {
        let outcome =
            std::panic::catch_unwind(|| store_conformance(|| Liar::new(lie), K, u16::from));
        let message = outcome.err().map(|p| match p.downcast::<String>() {
            Ok(s) => *s,
            Err(p) => p
                .downcast_ref::<&str>()
                .map(|s| (*s).to_owned())
                .unwrap_or_default(),
        });
        assert!(
            message.as_deref().is_some_and(|m| m.contains(case)),
            "{lie:?}: want a failure in {case:?}, got {message:?}"
        );
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Reader {
    Load,
    Guard,
    Raw,
}

// a store written from scratch, honest unless its one lie says otherwise
struct Liar {
    lie: Lie,
    rows: BTreeMap<K, (u16, Version, Option<UnixTime>)>,
    applied: BTreeMap<EffectId, BTreeSet<K>>,
    counter: u64,
    writes: u64,
    loaded_at: BTreeMap<K, u64>,
}

impl Liar {
    const fn new(lie: Lie) -> Self {
        Self {
            lie,
            rows: BTreeMap::new(),
            applied: BTreeMap::new(),
            counter: 0,
            writes: 0,
            loaded_at: BTreeMap::new(),
        }
    }

    fn live(&self, k: &K, now: UnixTime, reader: Reader) -> Option<Version> {
        let &(_, version, expiry) = self.rows.get(k)?;
        let alive = match expiry {
            None => true,
            Some(_) if reader == Reader::Raw => true,
            Some(_) if reader == Reader::Guard && self.lie == Lie::GuardsIgnoreExpiry => true,
            Some(t) if self.lie == Lie::LiveAtDeadline => now <= t,
            Some(t) => now < t,
        };
        alive.then_some(version)
    }

    fn write(&mut self, effect: &Effect<K, u16>, only: &BTreeSet<K>) {
        let mut wrote = false;
        for k in effect.deletes().filter(|k| only.contains(k)) {
            wrote = true;
            self.rows.remove(k);
        }
        for (k, &r, expiry) in effect.puts().filter(|(k, _, _)| only.contains(k)) {
            wrote = true;
            let old = self.rows.get(k).map(|row| row.1);
            let create = effect
                .guards()
                .any(|g| matches!(g, Guard::Absent(a) if a == k));
            self.counter += 1;
            let version = match (self.lie, old) {
                (Lie::RecreateAfterExpiryRepeats, Some(v)) if create => v,
                (Lie::VersionPerKey, Some(v)) => Version::new(v.get() + 1),
                (Lie::VersionPerKey, None) => Version::new(1),
                _ => Version::new(self.counter),
            };
            let expiry = if self.lie == Lie::UpdateDropsExpiry && old.is_some() {
                None
            } else {
                expiry
            };
            self.rows.insert(k.clone(), (r, version, expiry));
        }
        self.writes += u64::from(wrote);
    }

    fn bump(&mut self, k: &K) {
        self.counter += 1;
        if let Some(row) = self.rows.get_mut(k) {
            row.1 = Version::new(self.counter);
        }
    }
}

impl Store<K, u16> for Liar {
    type Error = Fault;

    fn load(&mut self, keys: &[K], now: UnixTime) -> Result<Rows<K, u16>, Fault> {
        let mut rows = Rows::new();
        for k in keys {
            self.loaded_at.insert(k.clone(), self.writes);
            let row = self
                .live(k, now, Reader::Load)
                .and_then(|v| self.rows.get(k).map(|r| Row::new(r.0, v)));
            rows.insert(k.clone(), row);
        }
        Ok(rows)
    }

    fn apply(
        &mut self,
        effect: &Effect<K, u16>,
        now: UnixTime,
    ) -> Result<Result<Receipt, Conflict<K>>, Fault> {
        let lie = self.lie;
        let keys: BTreeSet<K> = effect.guards().map(|g| (*g.key()).clone()).collect();
        let seen_id = self.applied.get(&effect.id()).map(|seen| *seen == keys);
        if seen_id == Some(false) && lie != Lie::IdOnly {
            return Err(Fault::ReusedId);
        }
        if seen_id.is_some() && lie != Lie::IdAfterGuards {
            return Ok(Ok(mint(effect)));
        }
        if lie == Lie::SmallBound && effect.guards().count() > 100
            || lie == Lie::SmallDeleteBound && effect.deletes().count() > 40
        {
            return Err(Fault::Lost);
        }
        let puts: BTreeSet<K> = effect.puts().map(|(k, _, _)| k.clone()).collect();
        let deletes: BTreeSet<K> = effect.deletes().cloned().collect();
        let creates: BTreeSet<K> = effect
            .guards()
            .filter_map(|g| match g {
                Guard::Absent(k) if puts.contains(k) => Some(k.clone()),
                _ => None,
            })
            .collect();
        let consumes: BTreeSet<K> = effect
            .guards()
            .filter_map(|g| match g {
                Guard::Consume(k) => Some(k.clone()),
                _ => None,
            })
            .collect();
        let checked = effect.check(|k| {
            if lie == Lie::UniqueAsError && creates.contains(k) {
                return None;
            }
            let raw = match lie {
                Lie::ConsumeIgnoresExpiry => consumes.contains(k),
                Lie::WritesIgnoreExpiry => {
                    (puts.contains(k) || deletes.contains(k)) && !creates.contains(k)
                }
                _ => false,
            };
            let v = self.live(k, now, if raw { Reader::Raw } else { Reader::Guard })?;
            let stale = self.loaded_at.get(k).is_some_and(|&at| at < self.writes);
            Some(if lie == Lie::TableVersion && stale {
                Version::new(u64::MAX)
            } else {
                v
            })
        });
        if let Err(conflict) = checked {
            let first = conflict.failures().iter().map(|(k, _)| k.clone()).min();
            match lie {
                Lie::ConflictAsError => return Err(Fault::Lost),
                Lie::RecordsConflictedId => {
                    self.applied.insert(effect.id(), keys);
                }
                Lie::EagerPuts => self.write(effect, &puts),
                Lie::EagerDeletes => self.write(effect, &deletes),
                Lie::StopAtFirstFailure => {
                    let before: BTreeSet<K> = puts
                        .union(&deletes)
                        .filter(|k| Some(*k) < first.as_ref())
                        .cloned()
                        .collect();
                    self.write(effect, &before);
                }
                _ => {}
            }
            return Ok(Err(conflict));
        }
        if seen_id.is_some() {
            return Ok(Ok(mint(effect)));
        }
        if lie == Lie::UniqueAsError && creates.iter().any(|k| self.rows.contains_key(k)) {
            return Err(Fault::Lost);
        }
        if lie != Lie::SkipWrites {
            self.write(effect, &puts.union(&deletes).cloned().collect());
        }
        if lie == Lie::ExpectBumps {
            let expected: Vec<K> = effect
                .guards()
                .filter_map(|g| match g {
                    Guard::Unchanged(k, _) if !puts.contains(k) && !deletes.contains(k) => {
                        Some(k.clone())
                    }
                    _ => None,
                })
                .collect();
            expected.iter().for_each(|k| self.bump(k));
        }
        if lie == Lie::ConsumeSweepsSibling {
            for k in &consumes {
                self.rows.remove(&K(k.0 ^ 1));
            }
        }
        if lie == Lie::UpdateRewritesSibling
            && puts.contains(&K(0))
            && !creates.contains(&K(0))
            && let Some(row) = self.rows.get_mut(&K(1))
        {
            row.0 = u16::MAX;
        }
        if lie != Lie::NoAppliedId {
            self.applied.insert(effect.id(), keys);
        }
        if lie == Lie::WrongReceipt {
            let other = Effect::builder(&mut testkit::seeded(0))
                .expect_absent(K(0))
                .build();
            return Ok(Ok(other.map_or_else(|_| mint(effect), |o| mint(&o))));
        }
        Ok(Ok(mint(effect)))
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "the lying store's one receipt mint"
)]
fn mint(effect: &Effect<K, u16>) -> Receipt {
    effect.host_applied()
}

type Backing = Arc<Mutex<MemStore<K, u16>>>;

// every handle shares one backing store; the lock is the transaction
struct Shared(Backing);

impl Shared {
    fn lock(&self) -> MutexGuard<'_, MemStore<K, u16>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Store<K, u16> for Shared {
    type Error = Fault;

    fn load(&mut self, keys: &[K], now: UnixTime) -> Result<Rows<K, u16>, Fault> {
        self.lock().load(keys, now)
    }

    fn apply(
        &mut self,
        effect: &Effect<K, u16>,
        now: UnixTime,
    ) -> Result<Result<Receipt, Conflict<K>>, Fault> {
        self.lock().apply(effect, now)
    }
}

#[test]
fn a_shared_memstore_consumes_once() {
    let backing = Backing::default();
    store_conformance_shared(|| Shared(backing.clone()), K, u16::from);
}

#[derive(Default)]
struct Table {
    rows: BTreeMap<K, (u16, Version)>,
    writes: u64,
}

type SharedTable = Arc<Mutex<Table>>;

// holds each arrival until RACERS have come, or gives up after a while so a stray early conflict fails the
// test instead of hanging it; arrivals add up across the rounds of one test
#[derive(Default)]
struct Window {
    arrived: Mutex<usize>,
    gate: Condvar,
}

impl Window {
    fn wait(&self) {
        let mut arrived = self.arrived.lock().unwrap_or_else(PoisonError::into_inner);
        *arrived += 1;
        let release = arrived.div_ceil(RACERS) * RACERS;
        if *arrived >= release {
            self.gate.notify_all();
            return;
        }
        let _ = self
            .gate
            .wait_timeout_while(arrived, Duration::from_secs(10), |n| *n < release);
    }
}

// the READ COMMITTED failure for one kind of racing effect: its guards are checked in one transaction and its
// writes land in the next, with every racer between the two so the interleaving is certain; every other effect,
// the seeding creates included, is atomic
#[derive(Clone, Copy)]
enum Racy {
    Consume,
    Update,
    Delete,
}

struct CheckThenWrite {
    table: SharedTable,
    window: Arc<Window>,
    racy: Racy,
}

impl CheckThenWrite {
    fn rows(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn races(&self, effect: &Effect<K, u16>) -> bool {
        let unchanged = effect.guards().any(|g| matches!(g, Guard::Unchanged(..)));
        match self.racy {
            Racy::Consume => effect.guards().any(|g| matches!(g, Guard::Consume(_))),
            Racy::Update => unchanged && effect.puts().next().is_some(),
            Racy::Delete => {
                unchanged && effect.deletes().next().is_some() && effect.puts().next().is_none()
            }
        }
    }
}

impl Store<K, u16> for CheckThenWrite {
    type Error = Fault;

    fn load(&mut self, keys: &[K], _now: UnixTime) -> Result<Rows<K, u16>, Fault> {
        let table = self.rows();
        let mut rows = Rows::new();
        for k in keys {
            rows.insert(k.clone(), table.rows.get(k).map(|&(r, v)| Row::new(r, v)));
        }
        Ok(rows)
    }

    fn apply(
        &mut self,
        effect: &Effect<K, u16>,
        _now: UnixTime,
    ) -> Result<Result<Receipt, Conflict<K>>, Fault> {
        let mut table = self.rows();
        if let Err(conflict) = effect.check(|k| table.rows.get(k).map(|row| row.1)) {
            return Ok(Err(conflict));
        }
        if self.races(effect) {
            drop(table);
            self.window.wait();
            table = self.rows();
        }
        for k in effect.deletes() {
            table.rows.remove(k);
        }
        for (k, &r, _) in effect.puts() {
            table.writes += 1;
            let version = Version::new(table.writes);
            table.rows.insert(k.clone(), (r, version));
        }
        Ok(Ok(mint(effect)))
    }
}

#[test]
fn a_check_then_write_store_double_spends_in_each_round() {
    for (racy, case) in [
        (Racy::Consume, "shared_consume: "),
        (Racy::Update, "shared_update: "),
        (Racy::Delete, "shared_delete: "),
    ] {
        let (table, window) = (SharedTable::default(), Arc::new(Window::default()));
        let outcome = std::panic::catch_unwind(|| {
            store_conformance_shared(
                || CheckThenWrite {
                    table: table.clone(),
                    window: window.clone(),
                    racy,
                },
                K,
                u16::from,
            );
        });
        let message = outcome.err().and_then(|p| p.downcast::<String>().ok());
        assert!(
            message
                .as_deref()
                .is_some_and(|m| m.contains(&format!("{case}exactly one racer wins the row"))),
            "{case}want more than one winner, got {message:?}"
        );
    }
}
