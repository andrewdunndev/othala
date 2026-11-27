//! `jwt_claims`: the input's first two segments re-signed under the jose-derived/claims.json HS256 key, so every
//! input reaches the header and claims checks, then read under that file's policy at its `now`.
use jose::{
    Audience, ErrorKind, Hs256, Issuer, Jwt, Leeway, Policy, SecretJwk, Signer, TokenKind, Typ,
};

const KEY: &[u8] = br#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;

struct AccessToken;

impl TokenKind for AccessToken {
    const TYP: Typ = Typ::Explicit("at+jwt");
    type Claims = serde::de::IgnoredAny;
}

fn run(data: &[u8]) -> Result<(), jose::Error> {
    let secret = SecretJwk::decode(KEY)?;
    let text = String::from_utf8_lossy(data);
    let mut segments = text.splitn(3, '.');
    let token = match (segments.next(), segments.next()) {
        (Some(header), Some(payload)) => {
            let input = format!("{header}.{payload}");
            let signature = secret.signing_key::<Hs256>()?.sign(input.as_bytes())?;
            format!("{input}.{}", base::b64url_encode(&signature))
        }
        _ => text.into_owned(),
    };
    let policy = Policy::<AccessToken>::new(
        Issuer::new("https://issuer.example")?,
        Audience::new("client-1")?,
        Leeway::new(60)?,
    )?;
    let jwt = Jwt::parse(&token)?.verify(&secret.verify_key::<Hs256>()?)?;
    jwt.claims(&policy, base::UnixTime::new(1_700_000_000))
        .map(drop)
}

/// The outcome of the claims read, or of the first step that refused.
pub(crate) fn check(data: &[u8]) -> Result<(), ErrorKind> {
    run(data).map_err(|e| e.kind())
}
