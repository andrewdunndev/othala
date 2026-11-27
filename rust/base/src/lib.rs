//! Shared vocabulary for the identity primitives: time, entropy, secrets,
//! digests, strict base64url, and the one store-effect contract.
//!
//! A decision reads rows and returns its verdict in a [`Pending`] beside the [`Effect`] that makes it true;
//! the verdict counts only once a [`Store`] has applied that effect and answered its [`Receipt`]:
//!
//! ```
//! use base::{Effect, Entropy, Failure, Pending, Rows, Scope, Slot, Store, StoreKey, UnixTime};
//! use testkit::{MemStore, seeded};
//!
//! #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
//! struct Ticket(u8);
//!
//! impl StoreKey for Ticket {
//!     fn scope(&self) -> Scope {
//!         Scope::Global
//!     }
//! }
//!
//! // a ticket admits once: the verdict is its record, and the effect consumes its row
//! fn redeem(rows: &Rows<Ticket, &'static str>, e: &mut impl Entropy) -> Option<Pending<&'static str, Ticket, &'static str>> {
//!     let Some(Slot::Row(row)) = rows.get(&Ticket(1)) else {
//!         return None;
//!     };
//!     Some(Pending::new(*row.record(), Effect::consumed(e, Ticket(1))))
//! }
//!
//! let (now, e) = (UnixTime::new(1_000), &mut seeded(1));
//! let mut store = MemStore::new();
//! let created = Effect::created(e, Ticket(1), "admit one", None);
//! let receipt = store.apply(&created, now).unwrap().unwrap();
//! assert_eq!(receipt.effect_id(), created.id());
//!
//! // two decisions over the same rows race; the first to apply wins
//! let rows = store.load(&[Ticket(1)], now).unwrap();
//! let (first, second) = (redeem(&rows, e).unwrap(), redeem(&rows, e).unwrap());
//! let receipt = store.apply(first.effect(), now).unwrap().unwrap();
//! assert_eq!(first.settle(receipt).unwrap(), "admit one");
//!
//! // the loser's guard fails, so its verdict never settles; re-decided on fresh rows, nothing is left to redeem
//! let conflict = store.apply(second.effect(), now).unwrap().unwrap_err();
//! assert_eq!(conflict.failures(), [(Ticket(1), Failure::Missing)]);
//! let rows = store.load(&[Ticket(1)], now).unwrap();
//! assert!(redeem(&rows, e).is_none());
//! ```
#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod b64url;
mod effect;
mod entropy;
mod error;
mod secret;
mod store;
mod time;

pub use b64url::{MAX_B64URL_TEXT, b64url_decode, b64url_encode};
pub use effect::{
    Builder, Conflict, Effect, EffectId, Failure, Guard, MAX_EFFECT_SIZE, Pending, Receipt,
};
pub use entropy::Entropy;
#[cfg(feature = "rand_core")]
pub use entropy::RandCore;
pub use error::{Error, ErrorKind};
pub use secret::{BrowserBinding, Digest, Secret, SecretBytes};
pub use store::{REDECIDE, Retry, Row, Rows, Scope, Slot, Store, StoreKey, Version};
pub use time::UnixTime;
