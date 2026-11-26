//! The reference store's injected faults.
use base::{Effect, Pending, Scope, Store, StoreKey, UnixTime};
use store::{Fault, MemStore};
use testkit::seeded;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct K(u8);

impl StoreKey for K {
    fn scope(&self) -> Scope {
        Scope::Global
    }
}

const NOW: UnixTime = UnixTime::new(1);

fn create(seed: u64, k: u8) -> Result<Effect<K, u8>, base::Error> {
    Effect::builder(&mut seeded(seed))
        .create(K(k), k, None)
        .build()
}

#[test]
fn a_lost_result_commits_and_a_reapply_settles() -> Result<(), Box<dyn std::error::Error>> {
    let mut s = MemStore::<K, u8>::new();
    s.lose_next_result().lose_next_result();
    let a = Pending::new('a', create(1, 1)?);
    let b = create(2, 2)?;
    assert_eq!(s.apply(a.effect(), NOW).err(), Some(Fault::Lost));
    assert_eq!(s.apply(&b, NOW).err(), Some(Fault::Lost));
    assert_eq!(s.contents(NOW).len(), 2, "both lost results committed");
    let Ok(Ok(receipt)) = s.apply(a.effect(), NOW) else {
        return Err("a re-apply after a lost result settles".into());
    };
    assert_eq!(a.settle(receipt).ok(), Some('a'));
    assert!(
        matches!(s.apply(&create(3, 3)?, NOW), Ok(Ok(_))),
        "losses spent"
    );
    assert_eq!(s.contents(NOW).len(), 3);
    Ok(())
}
