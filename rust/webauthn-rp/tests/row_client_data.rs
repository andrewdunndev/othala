//! Row `client_data`: the oracle's `client-data.json` through the bounded reader, `Origin` and `RpId`; no public constructor reaches the reader before webauthn-04.
//! The reader is compiled into this crate from `src/`, so a mutant of it fails here.
#![expect(
    dead_code,
    reason = "the parts of the readers the public constructors reach"
)]
extern crate alloc;
use webauthn_rp::{MAX_CLIENT_DATA_DEPTH, MAX_CLIENT_DATA_JSON};

#[path = "../src/client_data.rs"]
mod client_data;
#[path = "../src/error.rs"]
pub mod error;
#[path = "support/hex.rs"]
mod hex;
#[path = "support/client_data.rs"]
mod oracle;

#[test]
fn client_data() {
    oracle::cases();
}

#[test]
fn json_bounds() {
    oracle::bounds();
}
