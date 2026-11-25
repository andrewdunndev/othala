//! Shared vocabulary for the identity primitives: time, entropy, secrets,
//! digests, strict base64url, and the one store-effect contract.
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
pub use secret::{Digest, Secret, SecretBytes};
pub use store::{REDECIDE, Retry, Row, Rows, Scope, Slot, Store, StoreKey, Version};
pub use time::UnixTime;
