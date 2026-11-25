//! Properties of `Effect` construction and of applying it to the reference store.
#![allow(clippy::unwrap_used, reason = "test helpers fail by panicking")]
use std::collections::{BTreeMap, BTreeSet};

use base::{
    Builder, Effect, ErrorKind, Failure, Guard, Row, Scope, Slot, Store, StoreKey, UnixTime,
    Version,
};
use proptest::prelude::*;
use testkit::{MemStore, seeded};

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

const NOW: UnixTime = UnixTime::new(10);
const STALE: Version = Version::new(u64::MAX);

#[derive(Clone, Copy, Debug)]
enum Kind {
    Create,
    Update,
    Consume,
    Delete,
    Expect,
    ExpectAbsent,
}

type Spec = Vec<(Kind, K, bool)>;

fn spec() -> impl Strategy<Value = Spec> {
    let kind = prop_oneof![
        Just(Kind::Create),
        Just(Kind::Update),
        Just(Kind::Consume),
        Just(Kind::Delete),
        Just(Kind::Expect),
        Just(Kind::ExpectAbsent)
    ];
    let key = prop_oneof![(0u8..6).prop_map(K::G), (0u8..6).prop_map(K::S)];
    prop::collection::vec((kind, key, any::<bool>()), 0..10)
}

fn build(
    spec: &Spec,
    seed: u64,
    seen: &BTreeMap<K, Version>,
) -> Result<Effect<K, u8>, base::Error> {
    let mut b: Builder<K, u8> = Effect::builder(&mut seeded(seed));
    for (i, &(kind, k, fresh)) in spec.iter().enumerate() {
        let v = seen.get(&k).copied().filter(|_| fresh).unwrap_or(STALE);
        let row = Row::new(0, v);
        let r = u8::try_from(i).unwrap();
        match kind {
            Kind::Create => b.create(k, r, None),
            Kind::Update => b.update(k, &row, r, None),
            Kind::Consume => b.consume(k),
            Kind::Delete => b.delete(k, &row),
            Kind::Expect => b.expect(k, &row),
            Kind::ExpectAbsent => b.expect_absent(k),
        };
    }
    b.build()
}

fn well_formed(e: &Effect<K, u8>) -> Result<(), TestCaseError> {
    let guards: Vec<Guard<&K>> = e.guards().collect();
    let keys: BTreeSet<&K> = guards.iter().map(|g| *g.key()).collect();
    prop_assert_eq!(keys.len(), guards.len(), "a key guarded twice");
    let puts: BTreeSet<&K> = e.puts().map(|(k, _, _)| k).collect();
    let deletes: BTreeSet<&K> = e.deletes().collect();
    prop_assert!(
        puts.is_subset(&keys) && deletes.is_subset(&keys),
        "a write without a guard"
    );
    prop_assert!(puts.is_disjoint(&deletes), "a key both put and deleted");
    for g in &guards {
        match g {
            Guard::Consume(k) => prop_assert!(deletes.contains(k)),
            Guard::Absent(k) => prop_assert!(!deletes.contains(k)),
            _ => {}
        }
    }
    Ok(())
}

fn distinct(spec: &Spec) -> bool {
    spec.iter().map(|s| s.1).collect::<BTreeSet<_>>().len() == spec.len()
}

proptest! {
    #[test]
    fn construction_never_unguarded(a in spec(), b in spec(), to_global in any::<bool>()) {
        let none = BTreeMap::new();
        let built = build(&a, 1, &none);
        let want = if !distinct(&a) { Err(ErrorKind::Overlap) } else if a.is_empty() { Err(ErrorKind::Empty) } else { Ok(()) };
        prop_assert_eq!(built.as_ref().map(|_| ()).map_err(|e| e.kind()), want);
        let (Ok(x), Ok(y)) = (built, build(&b, 2, &none)) else { return Ok(()) };
        well_formed(&x)?;
        let xs: BTreeSet<K> = x.guards().map(|g| **g.key()).collect();
        let ys: BTreeSet<K> = y.guards().map(|g| **g.key()).collect();
        match x.merge(y) {
            Ok(m) => {
                prop_assert!(xs.is_disjoint(&ys));
                well_formed(&m)?;
                prop_assert_eq!(m.guards().count(), xs.len() + ys.len());
            }
            Err(e) => prop_assert!(e.kind() == ErrorKind::Overlap && !xs.is_disjoint(&ys)),
        }
        let folded = |k: K| match k { K::G(n) if to_global => K::G(n / 2), K::S(n) => K::S(n / 2), k => k };
        let images: BTreeSet<K> = xs.iter().map(|&k| folded(k)).collect();
        match build(&a, 1, &none).unwrap().lift(folded, |r| r) {
            Ok(l) => {
                prop_assert_eq!(images.len(), xs.len());
                well_formed(&l)?;
            }
            Err(e) => prop_assert!(e.kind() == ErrorKind::Overlap && images.len() < xs.len()),
        }
    }

    #[test]
    fn all_guards_or_nothing(rows in prop::collection::vec((0u8..6).prop_map(K::G), 0..6), a in spec()) {
        let mut store = MemStore::<K, u8>::new();
        let present: BTreeSet<K> = rows.into_iter().collect();
        if !present.is_empty() {
            let mut b = Effect::builder(&mut seeded(3));
            present.iter().for_each(|&k| { b.create(k, 200, None); });
            prop_assert!(store.apply(&b.build().unwrap(), NOW).unwrap().is_ok());
        }
        let all: Vec<K> = (0..6).flat_map(|n| [K::G(n), K::S(n)]).collect();
        let loaded = store.load(&all, NOW).unwrap();
        let seen: BTreeMap<K, Version> = all.iter().filter_map(|k| match loaded.get(k) {
            Some(Slot::Row(r)) => Some((*k, r.version())),
            _ => None,
        }).collect();
        let Ok(effect) = build(&a, 4, &seen) else { return Ok(()) };
        let mut want: Vec<(K, Failure)> = effect.guards().filter_map(|g| match g {
            Guard::Consume(k) if !seen.contains_key(k) => Some((*k, Failure::Missing)),
            Guard::Unchanged(k, v) => match seen.get(k) {
                None => Some((*k, Failure::Missing)),
                Some(now) if *now != v => Some((*k, Failure::Changed)),
                _ => None,
            },
            Guard::Absent(k) if seen.contains_key(k) => Some((*k, Failure::Present)),
            _ => None,
        }).collect();
        want.sort_by_key(|f| f.0);
        let before = store.contents(NOW);
        match store.apply(&effect, NOW).unwrap() {
            Ok(_) => {
                prop_assert!(want.is_empty(), "applied although {:?} fail", want);
                let mut after = before.clone();
                effect.deletes().for_each(|k| { after.remove(k); });
                effect.puts().for_each(|(k, r, _)| { after.insert(*k, *r); });
                prop_assert_eq!(store.contents(NOW), after);
            }
            Err(conflict) => {
                let mut got = conflict.failures().to_vec();
                got.sort_by_key(|f| f.0);
                prop_assert_eq!(got, want);
                prop_assert_eq!(store.contents(NOW), before);
            }
        }
    }
}
