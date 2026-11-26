//! Row `derived`: the oracle family `vectors/webauthn-rp-derived/` (client-data, authenticator-data, registration and cbor); it proves CONTRACT R1 to R7, R33 to R53, R62, R70 to R81, R90, R145.
//! The cbor and client-data files reach the readers through `src/`, as rows `cbor` and `client_data` do; the others land with webauthn-04 (authenticator data and assertions) and 05 (registrations).
extern crate alloc;
use webauthn_rp::{MAX_CBOR_DEPTH, MAX_CBOR_ITEMS, MAX_CLIENT_DATA_DEPTH, MAX_CLIENT_DATA_JSON};

#[path = "../src/cbor.rs"]
mod cbor;
#[path = "../src/client_data.rs"]
mod client_data;
#[path = "../src/cose.rs"]
pub mod cose;
#[path = "../src/error.rs"]
pub mod error;
#[path = "support/hex.rs"]
mod hex;
#[path = "support/cbor.rs"]
mod oracle_cbor;
#[path = "support/client_data.rs"]
mod oracle_client_data;

#[test]
fn cbor() {
    oracle_cbor::cases();
}

#[test]
fn client_data() {
    oracle_client_data::cases();
}

#[test]
fn json_bounds() {
    oracle_client_data::bounds();
}
