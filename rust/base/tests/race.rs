//! The snapshot-race harness over small decisions, and probes that it catches what it claims to.
#![allow(clippy::unwrap_used, reason = "test helpers fail by panicking")]
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

fn read(s: &mut S, k: K) -> Option<base::Row<u8>> {
    let rows = s.load(&[k], NOW).unwrap();
    match rows.get(&k).unwrap() {
        Slot::Row(r) => Some(r.clone()),
        _ => None,
    }
}

fn claim(k: u8) -> Op {
    Box::new(move |s, e| {
        read(s, K(k)).is_none().then(|| {
            let mut b = Effect::builder(e);
            b.create(K(k), 1, None);
            b.build().unwrap()
        })
    })
}

fn bump(k: u8) -> Op {
    Box::new(move |s, e| {
        let mut b = Effect::builder(e);
        match read(s, K(k)) {
            Some(row) => b.update(K(k), &row, row.record() + 1, None),
            None => b.create(K(k), 1, None),
        };
        Some(b.build().unwrap())
    })
}

fn take(k: u8) -> Op {
    Box::new(move |s, e| {
        read(s, K(k)).map(|_| {
            let mut b = Effect::builder(e);
            b.consume(K(k));
            b.build().unwrap()
        })
    })
}

fn peek(k: u8, out: u8) -> Op {
    Box::new(move |s, e| {
        let row = read(s, K(k))?;
        read(s, K(out)).is_none().then(|| {
            let mut b = Effect::builder(e);
            b.expect(K(k), &row).create(K(out), *row.record(), None);
            b.build().unwrap()
        })
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
        let row = read(s, K(k))?;
        let mut seen = row.clone();
        if counted(&row) {
            calls.set(calls.get() + 1);
            if stale.contains(&calls.get()) {
                seen = Row::new(*row.record(), Version::new(u64::MAX));
            }
        }
        let mut b = Effect::builder(e);
        b.update(K(k), &seen, row.record() + 1, None);
        Some(b.build().unwrap())
    })
}

fn start() -> S {
    let mut s = S::new();
    let mut b = Effect::builder(&mut testkit::seeded(99));
    b.create(K(1), 5, None).create(K(4), 1, None);
    assert!(s.apply(&b.build().unwrap(), NOW).unwrap().is_ok());
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
    assert!(conflicts > 0, "pairs raced without a conflict");
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
    assert!(conflicts > 0, "triples raced without a conflict");
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
        let seen = read(s, K(1))?;
        let mut b = Effect::builder(e);
        b.create(K(9), *seen.record(), None);
        Some(b.build().unwrap())
    });
    race(&start(), &[sloppy.as_ref()], NOW);
}

#[test]
#[should_panic(expected = "against every serial run")]
fn consume_checks_existence_only() {
    let carry: Op = Box::new(|s, e| {
        let seen = read(s, K(1))?;
        let mut b = Effect::builder(e);
        b.consume(K(1)).create(K(9), *seen.record(), None);
        Some(b.build().unwrap())
    });
    race(&start(), &[bump(1).as_ref(), carry.as_ref()], NOW);
}
