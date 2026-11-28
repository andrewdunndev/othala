//! SigningKeys: RS256 public keys with a kid each, in order (CONTRACT R2, R3).
mod common;

use common::{Result, jwk, keys, text};
use jose::Jwk;
use oidc_provider::{ErrorKind, MAX_KEYS, SigningKeys};

fn kind(members: &[&str]) -> Result<core::result::Result<(), ErrorKind>> {
    let jwk = Jwk::decode(text(members)?.as_bytes())?;
    Ok(SigningKeys::new(vec![jwk])
        .map(|_| ())
        .map_err(|e| e.kind()))
}

#[test]
fn several_kids_keep_their_order() -> Result {
    let k = keys(&["k2", "k1", "k3"])?;
    assert_eq!(k.kids().collect::<Vec<_>>(), ["k2", "k1", "k3"]);
    Ok(())
}

#[test]
fn a_key_needs_a_kid_alg_rs256_and_use_sig() -> Result {
    let (kid, alg, usage) = (r#""kid":"k""#, r#""alg":"RS256""#, r#""use":"sig""#);
    assert_eq!(kind(&[kid, alg, usage])?, Ok(()));
    assert_eq!(kind(&[alg, usage])?, Err(ErrorKind::Missing));
    assert_eq!(kind(&[kid, usage])?, Err(ErrorKind::Malformed));
    assert_eq!(kind(&[kid, alg])?, Err(ErrorKind::Malformed));
    assert_eq!(
        kind(&[kid, alg, r#""use":"enc""#])?,
        Err(ErrorKind::Malformed)
    );
    assert_eq!(
        kind(&[kid, r#""alg":"RS384""#, usage])?,
        Err(ErrorKind::Malformed)
    );
    assert_eq!(
        kind(&[kid, r#""alg":"PS256""#, usage])?,
        Err(ErrorKind::Malformed)
    );
    Ok(())
}

#[test]
fn an_ec_key_naming_rs256_is_malformed() -> Result {
    let ec = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"k","alg":"RS256","use":"sig"}"#;
    let r = SigningKeys::new(vec![Jwk::decode(ec.as_bytes())?]);
    assert_eq!(
        r.map(|_| ()).map_err(|e| e.kind()),
        Err(ErrorKind::Malformed)
    );
    Ok(())
}

#[test]
fn a_repeated_kid_is_duplicate() -> Result {
    let r = SigningKeys::new(vec![jwk("k")?, jwk("j")?, jwk("k")?]);
    assert_eq!(
        r.map(|_| ()).map_err(|e| e.kind()),
        Err(ErrorKind::Duplicate)
    );
    Ok(())
}

#[test]
fn the_count_is_bounded() -> Result {
    let kids: Vec<String> = (0..=MAX_KEYS).map(|i| format!("k{i}")).collect();
    let ok = SigningKeys::new(
        kids.iter()
            .take(MAX_KEYS)
            .map(|k| jwk(k))
            .collect::<Result<_>>()?,
    )?;
    assert_eq!(ok.kids().count(), MAX_KEYS);
    let over = SigningKeys::new(kids.iter().map(|k| jwk(k)).collect::<Result<_>>()?);
    assert_eq!(
        over.map(|_| ()).map_err(|e| e.kind()),
        Err(ErrorKind::TooLarge)
    );
    assert_eq!(
        SigningKeys::new(Vec::new())
            .map(|_| ())
            .map_err(|e| e.kind()),
        Err(ErrorKind::Missing)
    );
    Ok(())
}

#[test]
fn each_error_kind_reads_distinctly() -> Result {
    let dup = SigningKeys::new(vec![jwk("k")?, jwk("k")?])
        .err()
        .ok_or("accepted")?;
    let none = SigningKeys::new(Vec::new()).err().ok_or("accepted")?;
    let big = oidc_provider::IssuerUrl::parse(&"a".repeat(300))
        .err()
        .ok_or("accepted")?;
    let bad = oidc_provider::IssuerUrl::parse("x")
        .err()
        .ok_or("accepted")?;
    assert_eq!(dup.to_string(), "a kid is named twice");
    assert_eq!(none.to_string(), "a required value was not given");
    assert_eq!(big.to_string(), "value or list exceeds its bound");
    assert_eq!(bad.to_string(), "value outside its grammar or range");
    Ok(())
}

#[test]
fn a_1024_bit_rsa_key_is_refused_by_jose_as_weak() {
    let n = format!("{}8", "_".repeat(170));
    let text =
        format!(r#"{{"kty":"RSA","n":"{n}","e":"AQAB","kid":"k","alg":"RS256","use":"sig"}}"#);
    let verdict = Jwk::decode(text.as_bytes())
        .map(|_| ())
        .map_err(|e| e.kind());
    assert_eq!(verdict, Err(jose::ErrorKind::WeakKey));
}
