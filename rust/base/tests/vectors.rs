//! RFC 4648 section 10 through the testkit vector runner.
use base::{b64url_decode, b64url_encode};
use testkit::vector;
use testkit::vectors::{Outcome, run};

#[derive(serde::Deserialize)]
struct Case {
    encoding: String,
    input: String,
    output: String,
}

#[test]
fn rfc4648_section10() {
    let tally = run::<Case>(vector!("rfc4648/test-vectors.json"), 7, |c| {
        if c.encoding != "BASE64" {
            return Outcome::NotApplicable;
        }
        let unpadded = c.output.trim_end_matches('=');
        assert_eq!(b64url_encode(c.input.as_bytes()), unpadded, "{}", c.input);
        assert_eq!(
            b64url_decode(unpadded).unwrap(),
            c.input.as_bytes(),
            "{}",
            c.input
        );
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (28, 7));
}
