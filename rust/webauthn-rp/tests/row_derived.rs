//! Row `derived`: the oracle family `vectors/webauthn-rp-derived/` (client-data, authenticator-data, registration and cbor); it proves CONTRACT R1 to R7, R33 to R53, R62, R70 to R81, R90, R145.
//! The cbor file reaches the reader through `src/`, as row `cbor` does; the client-data and authenticator-data files run through start and finish; registrations land with webauthn-05.
#![expect(
    dead_code,
    reason = "the parts of the readers the public constructors reach"
)]
extern crate alloc;
use webauthn_rp::{MAX_CBOR_DEPTH, MAX_CBOR_ITEMS};

#[path = "../src/cbor.rs"]
mod cbor;
#[path = "../src/cose.rs"]
pub mod cose;
#[path = "../src/error.rs"]
pub mod error;
#[path = "support/hex.rs"]
mod hex;
#[path = "support/assertion.rs"]
mod oracle_assertion;
#[path = "support/cbor.rs"]
mod oracle_cbor;

#[test]
fn cbor() {
    oracle_cbor::cases();
}

#[test]
fn client_data() {
    oracle_assertion::cases(
        testkit::vector!("webauthn-rp-derived/client-data.json"),
        20,
        false,
    );
}

#[test]
fn authenticator_data() {
    oracle_assertion::cases(
        testkit::vector!("webauthn-rp-derived/authenticator-data.json"),
        20,
        false,
    );
}
