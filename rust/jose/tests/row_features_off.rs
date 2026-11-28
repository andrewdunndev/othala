//! With every feature off (CONTRACT R50): an ES512 token or key and an RSA-OAEP token, RFC 7520 section 6's included, are `UnsupportedAlg`, and the
//! registry names still parse.
#![cfg(not(any(feature = "es512", feature = "rsa-decrypt", feature = "rsa-sign")))]

mod common_figures;
mod common_sections;

use jose::{ErrorKind, Jwe, JweAlg, Jwk, Jws, SecretJwk, SigningAlg};
use serde::Deserialize;
use testkit::vector;
use testkit::vectors::{Appendix, Json, Outcome, run};

#[derive(Deserialize)]
struct Case {
    id: String,
    alg: String,
    jwe: Json,
    serialization: Option<String>,
}

fn kind<T>(result: Result<T, jose::Error>) -> Option<ErrorKind> {
    result.err().map(|e| e.kind())
}

fn joined(file: &[Appendix], section: &str, starts: &str) -> String {
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

fn figure(file: &testkit::vectors::Figures, example: &str, number: u32) -> String {
    let found = file.examples.iter().find(|e| e.example == example);
    found
        .and_then(|e| e.figures.iter().find(|f| f.figure == number))
        .map(|f| f.joined.clone())
        .unwrap_or_default()
}

/// `figure`, counted: a figure the file lacks is empty text, which a refusal would accept.
fn visit(
    file: &testkit::vectors::Figures,
    example: &str,
    number: u32,
    visited: &std::cell::Cell<usize>,
) -> String {
    let text = figure(file, example, number);
    assert!(!text.is_empty(), "figure {number} is not in the file");
    visited.set(visited.get() + 1);
    text
}

#[test]
fn es512_is_refused() {
    let visited = std::cell::Cell::new(0);
    let keys = common_figures::all(vector!("rfc7520/jwk.json"));
    assert_eq!(
        kind(Jwk::decode(visit(&keys, "3.1", 1, &visited).as_bytes())),
        Some(ErrorKind::UnsupportedAlg)
    );
    assert_eq!(
        kind(SecretJwk::decode(
            visit(&keys, "3.2", 2, &visited).as_bytes()
        )),
        Some(ErrorKind::UnsupportedAlg)
    );
    let appendix = common_sections::all(vector!("rfc7515/appendix-a4-a7.json"));
    let key = joined(&appendix, "A.4.1", "{\"kty\":\"EC\",\"crv\":\"P-521\"");
    assert_eq!(
        kind(SecretJwk::decode(key.as_bytes())),
        Some(ErrorKind::UnsupportedAlg)
    );
    let token = joined(&appendix, "A.4.1", "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.");
    assert_eq!(kind(Jws::parse(&token)), Some(ErrorKind::UnsupportedAlg));
    let signed = common_figures::all(vector!("rfc7520/jws.json"));
    assert_eq!(
        kind(Jws::parse(&visit(&signed, "4.3", 27, &visited))),
        Some(ErrorKind::UnsupportedAlg)
    );
    assert_eq!(
        kind(Jws::parse_json(
            visit(&signed, "4.3", 28, &visited).as_bytes()
        )),
        Some(ErrorKind::UnsupportedAlg)
    );
    assert_eq!(
        kind(Jws::parse_json(
            visit(&signed, "4.3", 29, &visited).as_bytes()
        )),
        Some(ErrorKind::UnsupportedAlg)
    );
    assert_eq!(SigningAlg::parse("ES512").ok(), Some(SigningAlg::Es512));
    // two keys and three 4.3 tokens
    assert_eq!(visited.get(), 5);
}

#[test]
fn rsa_oaep_is_refused() {
    let tally = run::<Case>(vector!("rfc7516/jwe.json"), 1, |case| {
        if case.alg != "RSA-OAEP" {
            return Outcome::NotApplicable;
        }
        let wire = case.jwe.parse::<String>();
        assert_eq!(
            kind(Jwe::parse(&wire)),
            Some(ErrorKind::UnsupportedAlg),
            "{}",
            case.id
        );
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (15, 6));
    let tally = run::<Case>(vector!("rfc7520/jwe-cases.json"), 1, |case| {
        if case.alg != "RSA-OAEP" {
            return Outcome::NotApplicable;
        }
        let compact = case.serialization.as_deref() == Some("compact");
        let wire = if compact {
            case.jwe.parse::<String>()
        } else {
            case.jwe.text().to_owned()
        };
        let outcome = if compact {
            Jwe::parse(&wire)
        } else {
            Jwe::parse_json(wire.as_bytes())
        };
        assert_eq!(
            kind(outcome),
            Some(ErrorKind::UnsupportedAlg),
            "{}",
            case.id
        );
        Outcome::Checked
    });
    assert_eq!(tally.checked(), 8);
    assert_eq!(JweAlg::parse("RSA-OAEP").ok(), Some(JweAlg::RsaOaep));
}

#[test]
fn nested_jwt_is_refused() {
    let file = common_figures::all(vector!("rfc7520/nesting.json"));
    let visited = std::cell::Cell::new(0);
    for number in [236, 237, 238] {
        let wire = visit(&file, "6.8", number, &visited);
        let outcome = if number == 236 {
            Jwe::parse(&wire)
        } else {
            Jwe::parse_json(wire.as_bytes())
        };
        assert_eq!(
            kind(outcome),
            Some(ErrorKind::UnsupportedAlg),
            "figure {number}"
        );
    }
    assert_eq!(visited.get(), 3);
}
