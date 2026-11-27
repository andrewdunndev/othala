//! The committed fuzz corpora (CONTRACT R62), replayed through each target's own property: no input panics, and a
//! seed named `<outcome>-NN` has that outcome (`ok`, or the `ErrorKind` name). The seeds are the vectors' inputs:
//! `jws_parse` rfc7515 (A.1 to A.3 and the A.6.4 and A.7 JSON forms), `jwt_claims` jose-derived/claims.json,
//! `jwe_parse` rfc7516 and rfc7520 jwe-cases, `jwk_decode` jose-derived keys and jwks, each with a few minimal inputs.
//! A file a fuzz run adds (a hash name) is replayed for panics only.
use jose::ErrorKind;

#[path = "../fuzz/property/jwe_parse.rs"]
mod jwe_parse;
#[path = "../fuzz/property/jwk_decode.rs"]
mod jwk_decode;
#[path = "../fuzz/property/jws_parse.rs"]
mod jws_parse;
#[path = "../fuzz/property/jwt_claims.rs"]
mod jwt_claims;

fn label(outcome: Result<(), ErrorKind>) -> String {
    outcome.map_or_else(|kind| format!("{kind:?}"), |()| String::from("ok"))
}

/// Replays `dir` and returns how many seeds named their outcome.
fn replay(dir: &str, check: fn(&[u8]) -> Result<(), ErrorKind>) -> usize {
    let files =
        testkit::fixture::files(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(dir));
    let mut named = 0;
    for (name, data) in files {
        let outcome = std::panic::catch_unwind(|| check(&data));
        assert!(outcome.is_ok(), "{dir}/{name} panicked");
        if let (Ok(outcome), Some((want, _))) = (outcome, name.split_once('-')) {
            assert_eq!(label(outcome), want, "{dir}/{name}");
            named += 1;
        }
    }
    named
}

#[test]
fn jws_parse_corpus() {
    assert_eq!(replay("fuzz/corpus/jws_parse", jws_parse::check), 23);
}

#[test]
fn jwt_claims_corpus() {
    assert_eq!(replay("fuzz/corpus/jwt_claims", jwt_claims::check), 26);
}

#[test]
fn jwe_parse_corpus() {
    assert_eq!(replay("fuzz/corpus/jwe_parse", jwe_parse::check), 78);
}

#[test]
fn jwk_decode_corpus() {
    assert_eq!(replay("fuzz/corpus/jwk_decode", jwk_decode::check), 33);
}
