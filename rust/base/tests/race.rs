//! The snapshot-race harness over small decisions, and probes that it catches what it claims to.
use std::cell::Cell;

use base::{Effect, Row, Scope, Slot, Store, StoreKey, UnixTime, Version};
use testkit::{Decide, MemStore, Seeded, race};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct K(u8);

impl StoreKey for K {
    fn scope(&self) -> Scope {
        Scope::Global
    }
}

type S = MemStore<K, u8>;
type Op = Box<dyn Fn(&mut S, &mut Seeded) -> Option<Effect<K, u8>>>;

const NOW: UnixTime = UnixTime::new(100);

// the outer None is a failed load, so the op that read makes no write
fn read(s: &mut S, k: K) -> Option<Option<base::Row<u8>>> {
    match s.load(&[k], NOW).ok()?.get(&k)? {
        Slot::Row(r) => Some(Some(r.clone())),
        _ => Some(None),
    }
}

fn claim(k: u8) -> Op {
    Box::new(move |s, e| {
        read(s, K(k))?
            .is_none()
            .then(|| Effect::created(e, K(k), 1, None))
    })
}

fn bump(k: u8) -> Op {
    Box::new(move |s, e| {
        Some(match read(s, K(k))? {
            Some(row) => Effect::updated(e, K(k), &row, row.record() + 1, None),
            None => Effect::created(e, K(k), 1, None),
        })
    })
}

fn take(k: u8) -> Op {
    Box::new(move |s, e| read(s, K(k))?.map(|_| Effect::consumed(e, K(k))))
}

fn peek(k: u8, out: u8) -> Op {
    Box::new(move |s, e| {
        let row = read(s, K(k))??;
        read(s, K(out))?.is_none().then_some(())?;
        Effect::builder(e)
            .expect(K(k), &row)
            .create(K(out), *row.record(), None)
            .build()
            .ok()
    })
}

// bump(k), except that the calls listed in `stale` guard a version no store ever issued
fn flaky(
    k: u8,
    counted: impl Fn(&Row<u8>) -> bool + 'static,
    stale: std::ops::RangeInclusive<u8>,
) -> Op {
    let calls = Cell::new(0u8);
    Box::new(move |s, e| {
        let row = read(s, K(k))??;
        let mut seen = row.clone();
        if counted(&row) {
            calls.set(calls.get() + 1);
            if stale.contains(&calls.get()) {
                seen = Row::new(*row.record(), Version::new(u64::MAX));
            }
        }
        Some(Effect::updated(e, K(k), &seen, row.record() + 1, None))
    })
}

fn start() -> S {
    let mut s = S::new();
    let b = Effect::builder(&mut testkit::seeded(99))
        .create(K(1), 5, None)
        .create(K(4), 1, None);
    assert!(
        b.build()
            .is_ok_and(|e| matches!(s.apply(&e, NOW), Ok(Ok(_))))
    );
    s
}

fn ops() -> Vec<Op> {
    vec![
        claim(1),
        claim(2),
        bump(1),
        bump(1),
        bump(4),
        take(1),
        take(4),
        peek(1, 2),
        peek(1, 3),
        peek(4, 2),
    ]
}

#[test]
fn pairs() {
    let all = ops();
    let mut conflicts = 0;
    for a in &all {
        for b in &all {
            let pair: [Decide<'_, K, u8>; 2] = [a.as_ref(), b.as_ref()];
            conflicts += race(&start(), &pair, NOW);
        }
    }
    assert_eq!(
        conflicts, 56,
        "pairs: the seeded run raced another number of conflicts"
    );
}

#[test]
fn triples() {
    let all = ops();
    let mut conflicts = 0;
    for (i, a) in all.iter().enumerate() {
        for b in all.iter().skip(i) {
            for c in all.iter().skip(i + 1) {
                let triple: [Decide<'_, K, u8>; 3] = [a.as_ref(), b.as_ref(), c.as_ref()];
                conflicts += race(&start(), &triple, NOW);
            }
        }
    }
    assert_eq!(
        conflicts, 1410,
        "triples: the seeded run raced another number of conflicts"
    );
}

#[test]
fn same_twice() {
    for op in ops() {
        assert_eq!(race(&start(), &[op.as_ref()], NOW), 0);
    }
}

#[test]
#[should_panic(expected = "op 0 applied twice")]
fn same_twice_catches_a_store_that_forgets_applied_ids() {
    let mut forgetful = start();
    forgetful.forget_applied_ids();
    race(&forgetful, &[claim(2).as_ref()], NOW);
}

#[test]
#[should_panic(expected = "winners wrote {}")]
fn a_loser_fails_only_on_winners_writes() {
    let second_call_stale = flaky(1, |_| true, 2..=2);
    race(&start(), &[second_call_stale.as_ref()], NOW);
}

// the loser's re-decisions see the winner's bump (record 6); sighting 1 is the serial run's
#[test]
fn a_loser_redecides_up_to_three_times() {
    let two_stale = flaky(1, |r| *r.record() == 6, 2..=3);
    assert_eq!(
        race(&start(), &[bump(1).as_ref(), two_stale.as_ref()], NOW),
        2
    );
}

#[test]
#[should_panic(expected = "op 1 still in conflict after 3 re-decisions")]
fn a_loser_gives_up_after_three() {
    let three_stale = flaky(1, |r| *r.record() == 6, 2..=4);
    race(&start(), &[bump(1).as_ref(), three_stale.as_ref()], NOW);
}

#[test]
#[should_panic(expected = "without guarding")]
fn read_set() {
    let sloppy: Op = Box::new(|s, e| {
        let seen = read(s, K(1))??;
        Some(Effect::created(e, K(9), *seen.record(), None))
    });
    race(&start(), &[sloppy.as_ref()], NOW);
}

#[test]
#[should_panic(expected = "against every serial run")]
fn consume_checks_existence_only() {
    let carry: Op = Box::new(|s, e| {
        let seen = read(s, K(1))??;
        Effect::builder(e)
            .consume(K(1))
            .create(K(9), *seen.record(), None)
            .build()
            .ok()
    });
    race(&start(), &[bump(1).as_ref(), carry.as_ref()], NOW);
}
