//! Properties of `Effect` construction and of applying it to the reference store.
#![expect(clippy::unwrap_used, reason = "test helpers fail by panicking")]
use std::collections::{BTreeMap, BTreeSet};

use base::{
    Builder, Effect, ErrorKind, Failure, Guard, Row, Scope, Slot, Store, StoreKey, UnixTime,
    Version,
};
use proptest::prelude::*;
use proptest::test_runner::RngSeed;
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

const SIZE_BOUND: usize = 128;

fn kind() -> impl Strategy<Value = Kind> {
    prop_oneof![
        Just(Kind::Create),
        Just(Kind::Update),
        Just(Kind::Consume),
        Just(Kind::Delete),
        Just(Kind::Expect),
        Just(Kind::ExpectAbsent)
    ]
}

fn pool(n: u8) -> Vec<K> {
    (0..n).flat_map(|i| [K::G(i), K::S(i)]).collect()
}

// distinct keys by construction, plus at times one key named again at a random place
fn spec(max: usize) -> impl Strategy<Value = Spec> {
    prop::sample::subsequence(pool(80), 0..=max)
        .prop_flat_map(|keys| {
            let n = keys.len();
            let again = (
                any::<prop::sample::Index>(),
                any::<prop::sample::Index>(),
                kind(),
            );
            (
                Just(keys),
                prop::collection::vec((kind(), any::<bool>()), n),
                prop::option::weighted(0.25, again),
            )
        })
        .prop_map(|(keys, ops, again)| {
            let mut spec: Spec = keys
                .into_iter()
                .zip(ops)
                .map(|(k, (kind, fresh))| (kind, k, fresh))
                .collect();
            if let Some((which, at, kind)) = again
                && let Some(&(_, k, _)) = spec.get(which.index(spec.len().max(1)))
            {
                spec.insert(at.index(spec.len() + 1), (kind, k, true));
            }
            spec
        })
}

const fn op_size(kind: Kind) -> usize {
    match kind {
        Kind::Expect | Kind::ExpectAbsent => 1,
        _ => 2,
    }
}

// the builder latches its first fault: past the bound first, then a key named twice
fn expected(spec: &Spec) -> Result<(), ErrorKind> {
    let mut seen = BTreeSet::new();
    let mut size = 0;
    for &(kind, k, _) in spec {
        size += op_size(kind);
        if size > SIZE_BOUND {
            return Err(ErrorKind::TooLarge);
        }
        if !seen.insert(k) {
            return Err(ErrorKind::Overlap);
        }
    }
    if spec.is_empty() {
        Err(ErrorKind::Empty)
    } else {
        Ok(())
    }
}

fn size(e: &Effect<K, u8>) -> usize {
    e.guards().count() + e.puts().count() + e.deletes().count()
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
        b = match kind {
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

// mostly holding guards against `present`, so whole applies and conflicts are both common
fn against(present: BTreeSet<K>) -> impl Strategy<Value = Spec> {
    prop::sample::subsequence(pool(6), 1..=8)
        .prop_flat_map(|keys| {
            let n = keys.len();
            (
                Just(keys),
                prop::collection::vec((prop::bool::weighted(0.85), 0u8..20), n),
            )
        })
        .prop_map(move |(keys, picks)| {
            keys.into_iter()
                .zip(picks)
                .map(|(k, (hold, v))| {
                    let (kinds, fresh): (&[Kind], bool) = match (hold, present.contains(&k)) {
                        (true, true) => (
                            &[Kind::Update, Kind::Consume, Kind::Delete, Kind::Expect],
                            true,
                        ),
                        (true, false) => (&[Kind::Create, Kind::ExpectAbsent], true),
                        (false, true) => (
                            &[
                                Kind::Create,
                                Kind::ExpectAbsent,
                                Kind::Update,
                                Kind::Delete,
                                Kind::Expect,
                            ],
                            false,
                        ),
                        (false, false) => (
                            &[Kind::Update, Kind::Consume, Kind::Delete, Kind::Expect],
                            true,
                        ),
                    };
                    let kind = kinds.get(usize::from(v) % kinds.len()).copied().unwrap();
                    (kind, k, fresh)
                })
                .collect()
        })
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: 512,
        rng_seed: RngSeed::Fixed(0x5eed_0001),
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn construction_never_unguarded(a in spec(100), b in spec(40), to_global in any::<bool>()) {
        let none = BTreeMap::new();
        let built = build(&a, 1, &none);
        prop_assert_eq!(built.as_ref().map(|_| ()).map_err(|e| e.kind()), expected(&a));
        let (Ok(x), Ok(y)) = (built, build(&b, 2, &none)) else { return Ok(()) };
        well_formed(&x)?;
        prop_assert!(size(&x) <= SIZE_BOUND);
        let xs: BTreeSet<K> = x.guards().map(|g| **g.key()).collect();
        let ys: BTreeSet<K> = y.guards().map(|g| **g.key()).collect();
        let sum = size(&x) + size(&y);
        match x.merge(y) {
            Ok(m) => {
                prop_assert!(xs.is_disjoint(&ys) && sum <= SIZE_BOUND);
                well_formed(&m)?;
                prop_assert_eq!(m.guards().count(), xs.len() + ys.len());
            }
            Err(e) if sum > SIZE_BOUND => prop_assert_eq!(e.kind(), ErrorKind::TooLarge),
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
    fn all_guards_or_nothing(
        (a, present) in prop::sample::subsequence(pool(6), 0..=12)
            .prop_map(|ks| ks.into_iter().collect::<BTreeSet<K>>())
            .prop_flat_map(|present| (against(present.clone()), Just(present)))
    ) {
        let mut store = MemStore::<K, u8>::new();
        if !present.is_empty() {
            let b = present.iter().fold(Effect::builder(&mut seeded(3)), |b, &k| b.create(k, 200, None));
            prop_assert!(store.apply(&b.build().unwrap(), NOW).unwrap().is_ok());
        }
        let all = pool(6);
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
