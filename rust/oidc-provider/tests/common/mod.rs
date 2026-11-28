//! Helpers the row files share: the RFC 7515 A.2 RSA public key under chosen members, and a provider built on it.
#![allow(dead_code, reason = "each row file uses some of these")]
use std::error::Error;

use jose::Jwk;
use oidc_provider::{IssuerUrl, Lifetimes, Provider, SigningKeys};
use serde::Deserialize;

pub(crate) type Result<T = ()> = core::result::Result<T, Box<dyn Error>>;

#[derive(Deserialize)]
struct File {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    jwk: Option<Material>,
}

#[derive(Deserialize)]
struct Material {
    n: Option<String>,
}

/// The modulus of RFC 7515 A.2's public key, from the committed vector.
pub(crate) fn modulus() -> Result<String> {
    let file: File = serde_json::from_str(include_str!("../../../vectors/rfc7515/jws.json"))?;
    file.cases
        .into_iter()
        .find(|c| c.id == "a2-rs256-valid")
        .and_then(|c| c.jwk)
        .and_then(|m| m.n)
        .ok_or_else(|| "the A.2 case holds no modulus".into())
}

/// A JWK text of that key with the given extra members, each already `"name":value` JSON.
pub(crate) fn text(members: &[&str]) -> Result<String> {
    let mut text = format!(r#"{{"kty":"RSA","n":"{}","e":"AQAB""#, modulus()?);
    for m in members {
        text.push(',');
        text.push_str(m);
    }
    text.push('}');
    Ok(text)
}

/// The A.2 key as a published signing key: `kid`, `alg` RS256 and `use` sig.
pub(crate) fn jwk(kid: &str) -> Result<Jwk> {
    let kid = format!(r#""kid":"{kid}""#);
    Ok(Jwk::decode(
        text(&[&kid, r#""alg":"RS256""#, r#""use":"sig""#])?.as_bytes(),
    )?)
}

pub(crate) fn keys(kids: &[&str]) -> Result<SigningKeys> {
    Ok(SigningKeys::new(
        kids.iter().map(|k| jwk(k)).collect::<Result<_>>()?,
    )?)
}

pub(crate) fn lifetimes() -> Result<Lifetimes> {
    Ok(Lifetimes::builder()
        .code(60)
        .access_token(3_600)
        .id_token(600)
        .ticket(300)
        .build()?)
}

pub(crate) fn provider(issuer: &str, kids: &[&str]) -> Result<Provider> {
    Ok(Provider::new(
        IssuerUrl::parse(issuer)?,
        lifetimes()?,
        keys(kids)?,
    )?)
}
