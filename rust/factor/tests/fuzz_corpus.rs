//! The committed corpora of the parser fuzz targets (CONTRACT R19, R27, R32, B8), replayed through each target's own
//! property: no input panics, and a seed named `<outcome>-NN` has that outcome (`ok`, or the `ErrorKind` name). The
//! seeds are the codes of the rfc4226, rfc6238 and factor-derived OTP vectors, the PHC strings and recovery codes
//! the row tests name with their refusals, and a few minimal inputs. A file a fuzz run adds (a hash name) is
//! replayed for panics only.
use factor::ErrorKind;

#[path = "../fuzz/property/otp_code_parse.rs"]
mod otp_code_parse;
#[path = "../fuzz/property/phc_parse.rs"]
mod phc_parse;
#[path = "../fuzz/property/recovery_code_parse.rs"]
mod recovery_code_parse;

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
fn otp_code_parse_corpus() {
    assert_eq!(
        replay("fuzz/corpus/otp_code_parse", otp_code_parse::check),
        26
    );
}

#[test]
fn phc_parse_corpus() {
    assert_eq!(replay("fuzz/corpus/phc_parse", phc_parse::check), 19);
}

#[test]
fn recovery_code_parse_corpus() {
    assert_eq!(
        replay(
            "fuzz/corpus/recovery_code_parse",
            recovery_code_parse::check
        ),
        15
    );
}
