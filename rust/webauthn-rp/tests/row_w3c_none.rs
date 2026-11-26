//! Row `w3c_none`: W3C L3 16.2 and 16.4 to 16.6 (`vectors/w3c-webauthn-3/none.json`), registered with no attestation and then authenticated; it proves CONTRACT R37, R38, R45, R51, R74.
#[path = "support/ceremony.rs"]
mod ceremony;
#[path = "support/none.rs"]
mod oracle;

#[test]
fn none_attestation() {
    oracle::cases();
}
