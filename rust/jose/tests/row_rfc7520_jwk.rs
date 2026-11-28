//! RFC 7520 section 3 keys decode (CONTRACT R23); the P-521 keys of 3.1 and 3.2 are checked in `row_es512`.
mod common_figures;

use std::collections::BTreeMap;

use jose::{ErrorKind, Jwk, Kty, SecretJwk};
use testkit::vector;

fn kind<T>(result: Result<T, jose::Error>) -> Option<ErrorKind> {
    result.err().map(|e| e.kind())
}

#[test]
fn rfc7520_section3() {
    let file = common_figures::all(vector!("rfc7520/jwk.json"));
    let (mut checked, mut not_applicable) = (0, Vec::new());
    for example in &file.examples {
        let figure = example.figures.last().and_then(|f| f.json.as_ref());
        assert!(figure.is_some(), "{} has no JSON figure", example.example);
        let Some(figure) = figure else { continue };
        let (json, members) = (
            figure.text().as_bytes(),
            figure.parse::<BTreeMap<String, String>>(),
        );
        let kid = members.get("kid").map(String::as_str);
        let kty = match members.get("kty").map(String::as_str) {
            Some("EC") => Kty::Ec,
            Some("RSA") => Kty::Rsa,
            _ => Kty::Oct,
        };
        let private = members.contains_key("d") || members.contains_key("k");
        match example.example.as_str() {
            "3.1" | "3.2" => not_applicable.push(example.example.clone()),
            _ if private => {
                let key = SecretJwk::decode(json).map_err(|e| e.kind());
                assert_eq!(key.as_ref().err(), None, "{}", example.example);
                let key = key.ok();
                assert_eq!(key.as_ref().map(SecretJwk::kty), Some(kty));
                assert_eq!(
                    key.as_ref().and_then(SecretJwk::kid).map(|k| k.as_str()),
                    kid
                );
                assert_eq!(
                    key.as_ref().and_then(SecretJwk::public).is_some(),
                    kty != Kty::Oct
                );
                assert_eq!(kind(Jwk::decode(json)), Some(ErrorKind::Malformed));
                checked += 1;
            }
            _ => {
                let key = Jwk::decode(json).map_err(|e| e.kind());
                assert_eq!(key.as_ref().err(), None, "{}", example.example);
                let key = key.ok();
                assert_eq!(key.as_ref().map(Jwk::kty), Some(kty));
                assert_eq!(key.as_ref().and_then(Jwk::kid).map(|k| k.as_str()), kid);
                assert_eq!(kind(SecretJwk::decode(json)), Some(ErrorKind::Malformed));
                checked += 1;
            }
        }
    }
    assert_eq!(
        (checked, not_applicable),
        (4, vec!["3.1".to_owned(), "3.2".to_owned()])
    );
    assert_eq!(file.examples.len(), 6);
}
