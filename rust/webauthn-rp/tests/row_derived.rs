//! Row `derived`: the oracle family `vectors/webauthn-rp-derived/` (client-data, authenticator-data, registration and cbor); it proves CONTRACT R1 to R7, R33 to R53, R62, R70 to R81, R90, R145.
//! The cbor file reaches the reader through `src/`, as row `cbor` does; the other files land with webauthn-03 (client data), 04 (authenticator data and assertions) and 05 (registrations).
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
