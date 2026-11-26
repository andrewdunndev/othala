//! Test harnesses for the identity primitives; a dev-dependency only.

mod conformance;
pub mod fixture;
mod race;
pub mod vectors;

pub use conformance::store_conformance;
pub use race::{Decide, race};
pub use store::{Fault, MemStore};

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng;

/// Deterministic entropy for tests.
pub type Seeded = base::RandCore<ChaCha20Rng>;

/// ChaCha20 seeded from `seed`, through the `rand_core` adapter. The same `seed` gives the same effect ids, so
/// draw every effect one store sees from one advancing source; a reused id with other keys is `Fault::ReusedId`.
pub fn seeded(seed: u64) -> Seeded {
    base::RandCore::new(ChaCha20Rng::seed_from_u64(seed))
}
