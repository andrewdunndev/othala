//! The committed fuzz corpora (CONTRACT R2, R3, R4, R6, R15, R16), replayed through each target's own property: no
//! input panics, and a seed named `<outcome>-NN` has that outcome (`ok`, or the `ErrorKind` name). The seeds are the
//! `webauthn-rp-derived` vectors' inputs (`registration`, `attestation-object`, `cbor`, `authenticator-data`,
//! `authentication`, `client-data` and `limits`) and the `tests/golden` rows, each with a few minimal inputs and the
//! golden rows cut or lengthened by a byte. A file a fuzz run adds (a hash name) is replayed for panics only.
use webauthn_rp::ErrorKind;

#[path = "../fuzz/property/attestation_object.rs"]
mod attestation_object;
#[path = "../fuzz/property/authenticator_data.rs"]
mod authenticator_data;
#[path = "../fuzz/property/client_data.rs"]
mod client_data;
#[path = "../fuzz/property/record.rs"]
mod record;

fn label(outcome: Result<(), ErrorKind>) -> String {
    outcome.map_or_else(|kind| format!("{kind:?}"), |()| String::from("ok"))
}

/// Replays `dir` and returns how many seeds named their outcome.
fn replay(dir: &str, check: fn(&[u8]) -> Result<(), ErrorKind>) -> usize {
    let files =
        testkit::fixture::files(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(dir));
    let mut named = 0;
    for (name, data) in files {
        let outcome = testkit::fixture::replay(&format!("{dir}/{name}"), || check(&data));
        if let Some((want, _)) = name.split_once('-') {
            assert_eq!(label(outcome), want, "{dir}/{name}");
            named += 1;
        }
    }
    named
}

#[test]
fn attestation_object_corpus() {
    assert_eq!(
        replay("fuzz/corpus/attestation_object", attestation_object::check),
        53
    );
}

#[test]
fn authenticator_data_corpus() {
    assert_eq!(
        replay("fuzz/corpus/authenticator_data", authenticator_data::check),
        18
    );
}

#[test]
fn client_data_corpus() {
    assert_eq!(replay("fuzz/corpus/client_data", client_data::check), 32);
}

#[test]
fn record_corpus() {
    assert_eq!(replay("fuzz/corpus/record", record::check), 55);
}
