//! RFC 7515 A.4 to A.7: the JSON serializations verify, the unsecured JWS is refused (CONTRACT R2, R15).
mod common_sections;

use jose::{Es256, Jwk, Jws, Kid, Rs256};
use serde::Deserialize;
use testkit::vector;
use testkit::vectors::{Json, Outcome, run};

#[derive(Deserialize)]
struct Case {
    id: String,
    jwk: Json,
}

/// The key of the RFC 7515 A.2 (RSA) or A.3 (EC) example, as the vectors carry it.
fn key(id: &str) -> Option<Jwk> {
    let mut text = String::new();
    let tally = run::<Case>(vector!("rfc7515/jws.json"), 1, |case| {
        if case.id == id {
            text = case.jwk.text().to_owned();
        }
        Outcome::Checked
    });
    assert_eq!(tally.checked(), tally.total());
    Jwk::decode(text.as_bytes()).ok()
}

fn block(file: &[testkit::vectors::Appendix], section: &str, starts: &str) -> String {
    let all = file
        .iter()
        .flat_map(|a| std::iter::once(&a.section).chain(a.subsections.iter()));
    let found = all
        .filter(|s| s.section == section)
        .flat_map(|s| s.blocks.iter());
    found
        .filter(|b| b.joined.starts_with(starts))
        .map(|b| b.joined.clone())
        .next()
        .unwrap_or_default()
}

#[test]
fn appendix_a4_to_a7() {
    let file = common_sections::all(vector!("rfc7515/appendix-a4-a7.json"));
    let (rsa, ec) = (key("a2-rs256-valid"), key("a3-es256-valid"));
    assert!(rsa.is_some() && ec.is_some());
    let rs = rsa.and_then(|k| k.verify_key::<Rs256>().ok());
    let es = ec.and_then(|k| k.verify_key::<Es256>().ok());
    let payload =
        b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    // A.6, general: both signatures verify, each under its own key, and the `kid`s are hints
    let general = block(&file, "A.6.4", "{\"payload\"");
    let kids = |text: &str| {
        Jws::parse_json(text.as_bytes()).map(|j| {
            j.kids()
                .iter()
                .map(Kid::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
    };
    assert_eq!(
        kids(&general).ok(),
        Some(vec![
            "2010-12-29".to_owned(),
            "e9bc097a-ce51-4036-9562-d2ade882db0d".to_owned()
        ])
    );
    let under_rs = Jws::parse_json(general.as_bytes())
        .and_then(|j| j.verify(rs.as_ref().ok_or(jose::ErrorKind::Malformed)?));
    let under_es = Jws::parse_json(general.as_bytes())
        .and_then(|j| j.verify(es.as_ref().ok_or(jose::ErrorKind::Malformed)?));
    assert_eq!(
        under_rs.ok().map(|p| p.bytes().to_vec()),
        Some(payload.to_vec())
    );
    assert_eq!(
        under_es.ok().map(|p| p.bytes().to_vec()),
        Some(payload.to_vec())
    );

    // A.7, flattened
    let flattened = block(&file, "A.7", "{\"payload\"");
    let verified = Jws::parse_json(flattened.as_bytes())
        .and_then(|j| j.verify(es.as_ref().ok_or(jose::ErrorKind::Malformed)?));
    assert_eq!(
        verified.ok().map(|p| p.bytes().to_vec()),
        Some(payload.to_vec())
    );
    let wrong = Jws::parse_json(flattened.as_bytes())
        .and_then(|j| j.verify(rs.as_ref().ok_or(jose::ErrorKind::Malformed)?));
    assert_eq!(
        wrong.err().map(|e| e.kind()),
        Some(jose::ErrorKind::AlgMismatch)
    );

    // A.5, unsecured: refused under every key
    let unsecured = block(&file, "A.5", "eyJhbGciOiJub25lIn0.");
    assert!(unsecured.ends_with('.'));
    for outcome in [
        Jws::parse(&unsecured)
            .and_then(|j| j.verify(rs.as_ref().ok_or(jose::ErrorKind::Malformed)?)),
        Jws::parse(&unsecured)
            .and_then(|j| j.verify(es.as_ref().ok_or(jose::ErrorKind::Malformed)?)),
    ] {
        assert_eq!(
            outcome.err().map(|e| e.kind()),
            Some(jose::ErrorKind::AlgMismatch)
        );
    }
    // A.4 is ES512, in `row_es512`
}

const H: &str = "eyJhbGciOiJIUzI1NiJ9";

fn kind(json: &str) -> Option<jose::ErrorKind> {
    Jws::parse_json(json.as_bytes()).err().map(|e| e.kind())
}

//= https://www.rfc-editor.org/rfc/rfc7515#section-3.2
//= type=test
//# In the JWS JSON Serialization, one or both of the JWS Protected Header and JWS Unprotected Header
//# MUST be present.
//= https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1
//= type=test
//# At least one of the "protected" and "header" members MUST be present for each signature/MAC
//# computation so that an "alg" Header Parameter value is conveyed.
#[test]
fn a_signature_needs_a_protected_or_unprotected_header() {
    let malformed = Some(jose::ErrorKind::Malformed);
    assert_eq!(kind(r#"{"payload":"AA","signature":"AQ"}"#), malformed);
    assert_eq!(
        kind(r#"{"payload":"AA","signatures":[{"signature":"AQ"}]}"#),
        malformed
    );
    let one = format!(r#"{{"protected":"{H}","signature":"AQ"}}"#);
    assert_eq!(
        kind(&format!(
            r#"{{"payload":"AA","signatures":[{one},{{"signature":"AQ"}}]}}"#
        )),
        malformed
    );
    // either member alone conveys `alg`
    assert_eq!(
        kind(&format!(r#"{{"payload":"AA",{}}}"#, &one[1..one.len() - 1])),
        None
    );
    let header = r#"{"payload":"AA","header":{"alg":"HS256"},"signature":"AQ"}"#;
    assert_eq!(kind(header), None);
}

//= https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1
//= type=test
//# payload The "payload" member MUST be present and contain the value BASE64URL(JWS Payload).
#[test]
fn the_payload_member_is_required_and_base64url() {
    let malformed = Some(jose::ErrorKind::Malformed);
    let sig = format!(r#"{{"protected":"{H}","signature":"AQ"}}"#);
    assert_eq!(kind(&format!(r#"{{"signatures":[{sig}]}}"#)), malformed);
    assert_eq!(
        kind(&format!(r#"{{"protected":"{H}","signature":"AQ"}}"#)),
        malformed
    );
    assert_eq!(
        kind(&format!(r#"{{"payload":"A+/=","signatures":[{sig}]}}"#)),
        malformed
    );
    assert_eq!(
        kind(&format!(r#"{{"payload":"AA","signatures":[{sig}]}}"#)),
        None
    );
}

//= https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1
//= type=test
//# signatures The "signatures" member value MUST be an array of JSON objects.
#[test]
fn signatures_is_an_array_of_objects() {
    let malformed = Some(jose::ErrorKind::Malformed);
    let sig = format!(r#"{{"protected":"{H}","signature":"AQ"}}"#);
    for bad in [
        "5",
        "null",
        r#""AQ""#,
        r#"{"protected":"x"}"#,
        r#"["AQ"]"#,
        "[1]",
        "[[]]",
        &format!("[{sig},7]"),
    ] {
        assert_eq!(
            kind(&format!(r#"{{"payload":"AA","signatures":{bad}}}"#)),
            malformed,
            "{bad}"
        );
    }
    assert_eq!(
        kind(&format!(r#"{{"payload":"AA","signatures":[{sig}]}}"#)),
        None
    );
}
