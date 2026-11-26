//! ES512 and the P-521 keys: Wycheproof, RFC 7515 A.4, RFC 7520 3.1, 3.2 and 4.3 (CONTRACT R2, R3, R6, R7, R23).
#![cfg(feature = "es512")]
mod common;
mod common_figures;
mod common_sections;

use jose::{Es512, Jwk, Jws, Kty, SecretJwk};
use testkit::vector;
use testkit::vectors::{Appendix, Expected, Outcome, Vector, wycheproof};

fn hex(text: &str) -> Vec<u8> {
    let parse = |pair: &[u8; 2]| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok();
    let bytes: Vec<u8> = text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .filter_map(parse)
        .collect();
    assert_eq!(bytes.len() * 2, text.len(), "{text}");
    bytes
}

/// The P-1363 file verifies and refuses as Wycheproof says; the DER file holds no signature this crate accepts.
fn wycheproof_file(file: Vector, p1363: bool, total: usize) {
    let tally = wycheproof(file, 100, |group, case| {
        let point = hex(group
            .public_key
            .as_ref()
            .and_then(|k| k.uncompressed.as_deref())
            .unwrap_or_default());
        assert_eq!(point.len(), 133);
        let coordinate = |range: std::ops::Range<usize>| {
            base::b64url_encode(point.get(range).unwrap_or_default())
        };
        let jwk = format!(
            r#"{{"kty":"EC","crv":"P-521","x":"{}","y":"{}"}}"#,
            coordinate(1..67),
            coordinate(67..133)
        );
        let key = Jwk::decode(jwk.as_bytes()).and_then(|jwk| jwk.verify_key::<Es512>());
        assert!(key.is_ok(), "{}", case.tc_id);
        let message = hex(case.msg.as_deref().unwrap_or_default());
        let signature = hex(case.sig.as_deref().unwrap_or_default());
        let outcome = key.and_then(|key| key.verify_signature(&message, &signature));
        match (p1363, case.result) {
            (_, Expected::Acceptable) => return Outcome::NotApplicable,
            (true, Expected::Valid) => assert!(outcome.is_ok(), "{}: {}", case.tc_id, case.comment),
            _ => assert!(outcome.is_err(), "{}: {}", case.tc_id, case.comment),
        }
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (total, total));
}

#[test]
fn wycheproof_p521() {
    wycheproof_file(
        vector!("wycheproof/ecdsa_secp521r1_sha512_p1363_test.json"),
        true,
        318,
    );
    wycheproof_file(
        vector!("wycheproof/ecdsa_secp521r1_sha512_test.json"),
        false,
        542,
    );
}

fn block(file: &[Appendix], section: &str, starts: &str) -> String {
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
fn rfc7515_a4() {
    let file = common_sections::all(vector!("rfc7515/appendix-a4-a7.json"));
    let private = block(&file, "A.4.1", "{\"kty\":\"EC\",\"crv\":\"P-521\"");
    let public = SecretJwk::decode(private.as_bytes())
        .ok()
        .and_then(|k| k.public());
    let key = serde_json::to_string(&public).unwrap_or_default();
    let token = block(&file, "A.4.1", "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.");
    let verified = common::verify("ES512", &key, &token);
    assert!(verified.is_ok(), "{token}");
    let (head, tail) = token.split_at(token.len() - 3);
    let tampered = format!(
        "{head}{}",
        if tail.starts_with('A') { "BBB" } else { "AAA" }
    );
    assert!(common::verify("ES512", &key, &tampered).is_err());
}

fn example(file: &testkit::vectors::Figures, number: &str, figure: u32) -> String {
    let found = file.examples.iter().find(|e| e.example == number);
    let found = found.and_then(|e| e.figures.iter().find(|f| f.figure == figure));
    found.map(|f| f.joined.clone()).unwrap_or_default()
}

#[test]
fn rfc7520_p521() {
    let keys = common_figures::all(vector!("rfc7520/jwk.json"));
    let (public, private) = (example(&keys, "3.1", 1), example(&keys, "3.2", 2));
    let (public, private) = (
        Jwk::decode(public.as_bytes()),
        SecretJwk::decode(private.as_bytes()),
    );
    assert!(public.is_ok() && private.is_ok());
    let (public, private) = (public.ok(), private.ok());
    assert_eq!(public.as_ref().map(Jwk::kty), Some(Kty::Ec));
    assert_eq!(private.as_ref().map(SecretJwk::kty), Some(Kty::Ec));
    let derived = private.and_then(|k| k.public());
    assert_eq!(
        derived.as_ref().map(Jwk::thumbprint),
        public.as_ref().map(Jwk::thumbprint)
    );

    // 4.3: the compact, general and flattened serializations verify under the 3.1 key
    let signed = common_figures::all(vector!("rfc7520/jws.json"));
    let key = public.and_then(|k| k.verify_key::<Es512>().ok());
    let verified =
        |outcome: Result<jose::Payload, jose::Error>| outcome.ok().map(|p| p.bytes().len());
    let compact = example(&signed, "4.3", 27);
    let general = example(&signed, "4.3", 28);
    let flattened = example(&signed, "4.3", 29);
    let lengths = [
        verified(
            Jws::parse(&compact)
                .and_then(|j| j.verify(key.as_ref().ok_or(jose::ErrorKind::Malformed)?)),
        ),
        verified(
            Jws::parse_json(general.as_bytes())
                .and_then(|j| j.verify(key.as_ref().ok_or(jose::ErrorKind::Malformed)?)),
        ),
        verified(
            Jws::parse_json(flattened.as_bytes())
                .and_then(|j| j.verify(key.as_ref().ok_or(jose::ErrorKind::Malformed)?)),
        ),
    ];
    let payload = compact
        .split('.')
        .nth(1)
        .and_then(|p| base::b64url_decode(p).ok());
    assert_eq!(lengths, [payload.map(|p| p.len()); 3]);
    assert!(lengths.iter().all(Option::is_some));
    let kids = Jws::parse_json(general.as_bytes()).map(|j| {
        j.kids()
            .iter()
            .map(|k| k.as_str().to_owned())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        kids.ok(),
        Some(vec!["bilbo.baggins@hobbiton.example".to_owned()])
    );
}
