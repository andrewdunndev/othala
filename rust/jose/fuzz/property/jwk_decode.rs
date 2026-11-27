//! `jwk_decode`: the input through every JWK and JWK Set decoder. `decode_public` keeps no key `decode` drops (R26b),
//! a private key's thumbprint is its public half's (RFC 7638 section 3.2.1), and a public key yields its thumbprint
//! and an ES256 key or a refusal.
use jose::{ErrorKind, Es256, Jwk, JwkSet, SecretJwk};

/// The outcome of `Jwk::decode`; the set decoders and `SecretJwk::decode` always run.
pub(crate) fn check(data: &[u8]) -> Result<(), ErrorKind> {
    let set = JwkSet::decode(data).map(|s| s.entries().len());
    let public = JwkSet::decode_public(data).map(|s| s.entries().len());
    if let (Ok(all), Ok(published)) = (&set, &public) {
        assert!(published <= all, "decode_public kept a key decode drops");
    }
    if let Ok(secret) = SecretJwk::decode(data)
        && let Some(half) = secret.public()
    {
        assert_eq!(
            half.thumbprint(),
            secret.thumbprint(),
            "a private key's thumbprint is its public half's"
        );
    }
    let jwk = Jwk::decode(data).map_err(|e| e.kind())?;
    let _digest = jwk.thumbprint();
    let _key = jwk.verify_key::<Es256>();
    Ok(())
}
