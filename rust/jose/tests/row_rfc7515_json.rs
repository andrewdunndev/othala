//! RFC 7515 A.4 to A.7: the JSON serializations verify, the unsecured JWS is refused (CONTRACT R2, R15).
use jose::{Es256, Jwk, Jws, Kid, Rs256};
use serde::Deserialize;
use testkit::vector;
use testkit::vectors::{Json, Outcome, run, sections};

#[derive(Deserialize)]
struct Case {
    id: String,
    jwk: Json,
}

/// The key of the RFC 7515 A.2 (RSA) or A.3 (EC) example, as the vectors carry it.
fn key(id: &str) -> Option<Jwk> {
    let mut text = String::new();
    run::<Case>(vector!("rfc7515/jws.json"), 1, |case| {
        if case.id == id {
            text = case.jwk.text().to_owned();
        }
        Outcome::Checked
    });
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
    let file = sections(vector!("rfc7515/appendix-a4-a7.json"));
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
