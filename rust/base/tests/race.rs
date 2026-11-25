//! The snapshot-race harness over small decisions, and probes that it catches what it claims to.
#![allow(clippy::unwrap_used, reason = "test helpers fail by panicking")]
use base::{Effect, Scope, Slot, Store, StoreKey, UnixTime};
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
    for a in &all {
        for b in &all {
            let pair: [Decide<'_, K, u8>; 2] = [a.as_ref(), b.as_ref()];
            race(&start(), &pair, NOW);
        }
    }
}

#[test]
fn triples() {
    let all = ops();
    for (i, a) in all.iter().enumerate() {
        for b in all.iter().skip(i) {
            for c in all.iter().skip(i + 1) {
                let triple: [Decide<'_, K, u8>; 3] = [a.as_ref(), b.as_ref(), c.as_ref()];
                race(&start(), &triple, NOW);
            }
        }
    }
}

#[test]
fn same_twice() {
    for op in ops() {
        race(&start(), &[op.as_ref()], NOW);
    }
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
