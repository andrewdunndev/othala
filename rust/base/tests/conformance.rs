//! The reference store against the store-effect obligation, and probes that the harness catches liars.
use base::{Conflict, Effect, Receipt, Rows, Scope, Store, StoreKey, UnixTime};
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

enum Lie {
    SkipWrites,
    ConflictAsError,
}

struct Liar(MemStore<K, u16>, Lie);

impl Store<K, u16> for Liar {
    type Error = Fault;

    fn load(&mut self, keys: &[K], now: UnixTime) -> Result<Rows<K, u16>, Fault> {
        self.0.load(keys, now)
    }

    #[expect(clippy::disallowed_methods, reason = "probe store")]
    fn apply(
        &mut self,
        effect: &Effect<K, u16>,
        now: UnixTime,
    ) -> Result<Result<Receipt, Conflict<K>>, Fault> {
        match self.1 {
            Lie::SkipWrites => Ok(Ok(effect.host_applied())),
            Lie::ConflictAsError => self.0.apply(effect, now)?.map(Ok).map_err(|_| Fault::Lost),
        }
    }
}

#[test]
#[should_panic(expected = "seeded row loads")]
fn catches_a_store_that_skips_writes() {
    store_conformance(|| Liar(MemStore::new(), Lie::SkipWrites), K, u16::from);
}

#[test]
#[should_panic(expected = "apply outcome known")]
fn catches_a_store_that_reports_conflict_as_error() {
    store_conformance(|| Liar(MemStore::new(), Lie::ConflictAsError), K, u16::from);
}
