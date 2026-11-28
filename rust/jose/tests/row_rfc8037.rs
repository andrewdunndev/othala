//! RFC 8037 Appendix A: Ed25519 keys, thumbprint, signing byte for byte and validation; X25519 and X448 refused
//! (CONTRACT R17, R24).
mod common_sections;

use jose::{EdDsa, ErrorKind, Header, Jwk, Jws, SecretJwk, Unsigned};
use testkit::vector;
use testkit::vectors::Appendix;

fn blocks<'a>(file: &'a [Appendix], section: &str) -> Vec<&'a testkit::vectors::Block> {
    let all = file
        .iter()
        .flat_map(|a| std::iter::once(&a.section).chain(a.subsections.iter()));
    all.filter(|s| s.section == section)
        .flat_map(|s| s.blocks.iter())
        .collect()
}

fn first_json(file: &[Appendix], section: &str) -> String {
    blocks(file, section)
        .first()
        .map(|b| b.joined.clone())
        .unwrap_or_default()
}

#[test]
fn appendix_a() {
    let file = common_sections::all(vector!("rfc8037/appendix-a.json"));
    let private = SecretJwk::decode(first_json(&file, "A.1").as_bytes());
    let public = Jwk::decode(
        blocks(&file, "A.2")
            .iter()
            .map(|b| b.joined.as_str())
            .find(|j| j.starts_with('{'))
            .unwrap_or_default()
            .as_bytes(),
    );
    assert_eq!(
        (
            private.as_ref().err().map(|e| e.kind()),
            public.as_ref().err().map(|e| e.kind())
        ),
        (None, None)
    );
    let (private, public) = (private.ok(), public.ok());
    assert_eq!(
        private
            .as_ref()
            .and_then(SecretJwk::public)
            .map(|k| k.thumbprint()),
        public.as_ref().map(Jwk::thumbprint)
    );

    // A.3: the thumbprint, as the RFC prints its hexadecimal
    let marker = "(inhexadecimal)of";
    let after = |j: &str| {
        j.split_once(marker)
            .and_then(|(_, rest)| rest.get(..64))
            .map(str::to_owned)
    };
    let hex = blocks(&file, "A.3").iter().find_map(|b| after(&b.joined));
    let digest: Option<String> = public.as_ref().map(|k| {
        k.thumbprint()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    });
    assert!(hex.is_some());
    assert_eq!(digest, hex);

    // A.4 and A.5: signing reproduces the RFC's token, and the token verifies
    let token = blocks(&file, "A.5")
        .iter()
        .map(|b| b.joined.clone())
        .find(|j| j.starts_with("eyJhbGciOiJFZERTQSJ9.") && j.matches('.').count() == 2);
    let token = token.unwrap_or_default();
    let body = token
        .split('.')
        .nth(1)
        .and_then(|p| base::b64url_decode(p).ok())
        .unwrap_or_default();
    assert!(!body.is_empty());
    let signing = private.and_then(|k| k.signing_key::<EdDsa>().ok());
    let issued = signing.as_ref().and_then(|key| {
        Unsigned::<EdDsa>::jws(Header::new(), &body)
            .ok()?
            .sign(key)
            .ok()
    });
    assert_eq!(issued.as_ref().map(|c| c.as_str()), Some(token.as_str()));
    let key = public.and_then(|k| k.verify_key::<EdDsa>().ok());
    let verified =
        Jws::parse(&token).and_then(|j| j.verify(key.as_ref().ok_or(ErrorKind::Malformed)?));
    assert_eq!(verified.ok().map(|p| p.bytes().to_vec()), Some(body));

    // A.6 and A.7: X25519 and X448 are not implemented
    for section in ["A.6", "A.7"] {
        let jwk = blocks(&file, section)
            .iter()
            .map(|b| b.joined.clone())
            .find(|j| j.starts_with('{'))
            .unwrap_or_default();
        assert_eq!(
            Jwk::decode(jwk.as_bytes()).err().map(|e| e.kind()),
            Some(ErrorKind::UnsupportedAlg),
            "{section}"
        );
    }
}
