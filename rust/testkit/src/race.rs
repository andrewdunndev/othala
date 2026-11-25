#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "a harness reports a failed claim by panicking"
)]
use std::collections::BTreeSet;
use std::fmt::Debug;

use base::{Effect, REDECIDE, Store, StoreKey, UnixTime};

use crate::{MemStore, Seeded, seeded};

/// A decision: reads through the store and returns the effect it would apply, or `None` for no write.
pub type Decide<'a, K, R> = &'a dyn Fn(&mut MemStore<K, R>, &mut Seeded) -> Option<Effect<K, R>>;

/// Decides every op against one snapshot of `start`, applies the effects in every order, and asserts:
/// each decision guards every key it loaded; an effect fails only on keys an earlier winner wrote, so
/// one that guards nothing a winner wrote applies; a loser re-decided within `REDECIDE` reaches the
/// state of some serial run; and an effect applied twice answers as it did once. Returns the conflicts raced.
pub fn race<K, R>(start: &MemStore<K, R>, ops: &[Decide<'_, K, R>], now: UnixTime) -> usize
where
    K: StoreKey + Debug,
    R: Clone + PartialEq + Debug,
{
    let orders = permutations(ops.len());
    let serials: Vec<_> = orders
        .iter()
        .map(|order| {
            let mut serial = start.clone();
            for &(i, op) in &pick(ops, order) {
                if let Some(effect) = decide(&serial, op, seed(i, 0)) {
                    assert!(
                        serial.apply(&effect, now).expect("reference store").is_ok(),
                        "serial {order:?}: op {i}"
                    );
                }
            }
            serial.contents(now)
        })
        .collect();
    let (mut conflicts, mut sequences) = (0, Vec::new());
    for order in &orders {
        let mut raced = start.clone();
        let mut written = BTreeSet::new();
        let mut sequence = Vec::new();
        for &(i, op) in &pick(ops, order) {
            sequence.push(i);
            let Some(effect) = decide(start, op, seed(i, 0)) else {
                continue;
            };
            match raced.apply(&effect, now).expect("reference store") {
                Ok(_) => written.extend(writes(&effect)),
                Err(conflict) => {
                    conflicts += 1;
                    let failed: BTreeSet<K> =
                        conflict.failures().iter().map(|(k, _)| k.clone()).collect();
                    assert!(
                        failed.is_subset(&written),
                        "{order:?}: op {i} failed on {failed:?}; winners wrote {written:?}"
                    );
                    written.extend(redecide(&mut raced, op, i, now));
                }
            }
        }
        sequences.push(sequence);
        let outcome = raced.contents(now);
        assert!(
            serials.contains(&outcome),
            "order {order:?} reached {outcome:?}, against every serial run {serials:?}"
        );
    }
    assert_eq!(sequences, orders, "every order raced");
    for (i, op) in ops.iter().enumerate() {
        let Some(effect) = decide(start, *op, seed(i, 0)) else {
            continue;
        };
        let mut twice = start.clone();
        let first = twice.apply(&effect, now).expect("reference store").is_ok();
        assert_eq!(
            twice.apply(&effect, now).expect("reference store").is_ok(),
            first,
            "op {i} applied twice"
        );
    }
    conflicts
}

fn decide<K, R>(state: &MemStore<K, R>, op: Decide<'_, K, R>, seed: u64) -> Option<Effect<K, R>>
where
    K: StoreKey + Debug,
    R: Clone,
{
    let mut view = state.clone();
    view.take_reads();
    let effect = op(&mut view, &mut seeded(seed))?;
    let guarded = guards(&effect);
    let unguarded: Vec<_> = view
        .take_reads()
        .into_iter()
        .filter(|k| !guarded.contains(k))
        .collect();
    assert!(
        unguarded.is_empty(),
        "decision loaded {unguarded:?} without guarding them"
    );
    Some(effect)
}

fn redecide<K, R>(
    state: &mut MemStore<K, R>,
    op: Decide<'_, K, R>,
    i: usize,
    now: UnixTime,
) -> BTreeSet<K>
where
    K: StoreKey + Debug,
    R: Clone,
{
    for round in 1..=REDECIDE {
        let Some(effect) = decide(state, op, seed(i, round)) else {
            return BTreeSet::new();
        };
        if state.apply(&effect, now).expect("reference store").is_ok() {
            return writes(&effect);
        }
    }
    panic!("op {i} still in conflict after {REDECIDE} re-decisions");
}

fn guards<K: StoreKey, R>(effect: &Effect<K, R>) -> BTreeSet<K> {
    effect.guards().map(|g| (*g.key()).clone()).collect()
}

fn writes<K: StoreKey, R>(effect: &Effect<K, R>) -> BTreeSet<K> {
    effect
        .puts()
        .map(|(k, _, _)| k)
        .chain(effect.deletes())
        .cloned()
        .collect()
}

fn pick<'a, K, R>(ops: &[Decide<'a, K, R>], order: &[usize]) -> Vec<(usize, Decide<'a, K, R>)> {
    order
        .iter()
        .filter_map(|&i| ops.get(i).map(|op| (i, *op)))
        .collect()
}

fn seed(op: usize, round: u8) -> u64 {
    u64::try_from(op).expect("op index") * 256 + u64::from(round)
}

pub(crate) fn permutations(n: usize) -> Vec<Vec<usize>> {
    let Some(last) = n.checked_sub(1) else {
        return vec![Vec::new()];
    };
    let mut out = Vec::new();
    for rest in permutations(last) {
        for at in 0..=rest.len() {
            let mut p = rest.clone();
            p.insert(at, last);
            out.push(p);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::permutations;

    #[test]
    fn every_order_once() {
        for (n, count) in [(0, 1), (1, 1), (2, 2), (3, 6), (4, 24)] {
            let orders = permutations(n);
            let distinct: BTreeSet<_> = orders.iter().cloned().collect();
            assert_eq!((orders.len(), distinct.len()), (count, count));
            assert!(orders.iter().all(|o| {
                let mut sorted = o.clone();
                sorted.sort_unstable();
                sorted == (0..n).collect::<Vec<_>>()
            }));
        }
    }
}
