//! Row `cbor`: the oracle's `cbor.json` through the strict reader and the ES256 COSE parser, which no public constructor reaches before webauthn-04.
//! The reader and parser are compiled into this crate from `src/`, so a mutant of either fails here.
extern crate alloc;
use webauthn_rp::{MAX_CBOR_DEPTH, MAX_CBOR_ITEMS};

#[path = "../src/cbor.rs"]
mod cbor;
#[path = "../src/cose.rs"]
pub mod cose;
#[path = "../src/error.rs"]
pub mod error;
#[path = "support/cbor.rs"]
mod support;

#[test]
fn cbor() {
    support::cases();
}
