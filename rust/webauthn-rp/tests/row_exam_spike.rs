//! Row `exam_spike`: the ES256 none assertion carried from the exam spike, `vectors/w3c-webauthn-3/exam-spike/assertion-none-es256.json`, through start and finish; it proves CONTRACT R80.
#[path = "support/browser.rs"]
mod browser;
#[path = "support/hex.rs"]
mod hex;
#[path = "support/assertion.rs"]
mod oracle;
#[path = "support/refusal.rs"]
mod refusal;

#[test]
fn exam_spike() {
    oracle::cases(
        testkit::vector!("w3c-webauthn-3/exam-spike/assertion-none-es256.json"),
        8,
        true,
    );
}
