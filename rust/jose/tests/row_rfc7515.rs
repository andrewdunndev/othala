//! RFC 7515 A.1 to A.3 and the refusals around them (CONTRACT R1, R4).
mod common;

use serde::Deserialize;
use testkit::vector;
use testkit::vectors::{Json, Outcome, run};

#[derive(Deserialize)]
struct Expect {
    ok: bool,
    kind: Option<String>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    alg: String,
    jwk: Json,
    jws: String,
    expect: Expect,
}

#[test]
fn rfc7515_appendix_a() {
    let tally = run::<Case>(vector!("rfc7515/jws.json"), 19, |case| {
        let outcome = common::verify(&case.alg, case.jwk.text(), &case.jws);
        assert_eq!(outcome.is_ok(), case.expect.ok, "{}", case.id);
        if let Some(named) = &case.expect.kind {
            assert_eq!(
                outcome.err().map(|e| format!("{:?}", e.kind())).as_ref(),
                Some(named),
                "{}",
                case.id
            );
        }
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (19, 19));
}
