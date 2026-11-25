//! The reference store against the store-effect obligation, and a table of lying stores, each caught by its own case.
use std::collections::{BTreeMap, BTreeSet};

use base::{
    Conflict, Effect, EffectId, Guard, Receipt, Row, Rows, Scope, Store, StoreKey, UnixTime,
    Version,
};
use testkit::{Fault, MemStore, store_conformance};

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
    NoAppliedId,
    IdAfterGuards,
    RecordsConflictedId,
    UniqueAsError,
    LiveAtDeadline,
    GuardsIgnoreExpiry,
    UpdateDropsExpiry,
    VersionPerKey,
    SmallBound,
    WrongReceipt,
}

const CAUGHT_IN: [(Lie, &str); 17] = [
    (Lie::SkipWrites, "atomic: "),
    (Lie::ConflictAsError, "atomic: "),
    (Lie::EagerPuts, "atomic: "),
    (Lie::EagerDeletes, "atomic: "),
    (Lie::StopAtFirstFailure, "fails_after_write: "),
    (Lie::ExpectBumps, "expect_shared: "),
    (Lie::TableVersion, "disjoint: "),
    (Lie::NoAppliedId, "reapply: "),
    (Lie::IdAfterGuards, "reapply: "),
    (Lie::RecordsConflictedId, "conflict_not_applied: "),
    (Lie::UniqueAsError, "duplicate_create: "),
    (Lie::LiveAtDeadline, "expired: "),
    (Lie::GuardsIgnoreExpiry, "expired: "),
    (Lie::UpdateDropsExpiry, "expired: "),
    (Lie::VersionPerKey, "recreate: "),
    (Lie::SmallBound, "at_bound: "),
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
}

// a store written from scratch, honest unless its one lie says otherwise
struct Liar {
    lie: Lie,
    rows: BTreeMap<K, (u16, Version, Option<UnixTime>)>,
    applied: BTreeSet<EffectId>,
    counter: u64,
    writes: u64,
    loaded_at: BTreeMap<K, u64>,
}

impl Liar {
    const fn new(lie: Lie) -> Self {
        Self {
            lie,
            rows: BTreeMap::new(),
            applied: BTreeSet::new(),
            counter: 0,
            writes: 0,
            loaded_at: BTreeMap::new(),
        }
    }

    fn live(&self, k: &K, now: UnixTime, reader: Reader) -> Option<Version> {
        let &(_, version, expiry) = self.rows.get(k)?;
        let alive = match expiry {
            None => true,
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
            self.counter += 1;
            let version = match (self.lie, old) {
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
        let seen_id = self.applied.contains(&effect.id());
        if seen_id && lie != Lie::IdAfterGuards {
            return Ok(Ok(mint(effect)));
        }
        if lie == Lie::SmallBound && effect.guards().count() > 100 {
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
        let checked = effect.check(|k| {
            if lie == Lie::UniqueAsError && creates.contains(k) {
                return None;
            }
            let v = self.live(k, now, Reader::Guard)?;
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
                    self.applied.insert(effect.id());
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
        if seen_id {
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
        if lie != Lie::NoAppliedId {
            self.applied.insert(effect.id());
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
