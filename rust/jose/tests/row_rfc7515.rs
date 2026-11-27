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

/// The vectors are pinned external files that name no kind, so the kind each refusal must carry is our contract's
/// (R4, R12), kept here by vector id; a refusing vector with no entry fails the row.
const REFUSALS: &[(&str, &str)] = &[
    ("a1-hs256-tampered-signature", "BadSignature"),
    ("a1-hs256-tampered-payload", "BadSignature"),
    ("a1-hs256-truncated-signature", "Malformed"),
    ("a1-hs256-no-signature", "BadSignature"),
    ("a2-rs256-tampered-signature", "BadSignature"),
    ("a2-rs256-tampered-payload", "BadSignature"),
    ("a2-rs256-truncated-signature", "Malformed"),
    ("a2-rs256-no-signature", "BadSignature"),
    ("a3-es256-tampered-signature", "BadSignature"),
    ("a3-es256-tampered-payload", "BadSignature"),
    ("a3-es256-truncated-signature", "Malformed"),
    ("a3-es256-no-signature", "BadSignature"),
    ("alg-none-unsigned", "AlgMismatch"),
    ("alg-mismatch-hs256-as-es256", "AlgMismatch"),
    ("alg-confusion-rs256-as-hs256", "AlgMismatch"),
    ("alg-mismatch-es256-key-wrong-alg", "AlgMismatch"),
];

#[test]
fn rfc7515_appendix_a() {
    let tally = run::<Case>(vector!("rfc7515/jws.json"), 19, |case| {
        let outcome = common::verify(&case.alg, case.jwk.text(), &case.jws);
        let kind = case.expect.kind.as_deref().or_else(|| {
            REFUSALS
                .iter()
                .find(|(id, _)| *id == case.id)
                .map(|(_, kind)| *kind)
        });
        testkit::vectors::assert_verdict(&outcome, case.expect.ok, kind, |e| e.kind(), &case.id);
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (19, 19));
}
