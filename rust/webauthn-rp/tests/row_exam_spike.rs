//! Row `exam_spike`: the ES256 none assertion carried from the exam spike, `vectors/w3c-webauthn-3/exam-spike/assertion-none-es256.json`, through start and finish; it proves CONTRACT R80.
#[path = "support/hex.rs"]
mod hex;
#[path = "support/assertion.rs"]
mod oracle;

#[test]
fn exam_spike() {
    oracle::cases(
        testkit::vector!("w3c-webauthn-3/exam-spike/assertion-none-es256.json"),
        8,
        true,
    );
}
