//! `jws_parse`: the input as compact and as JSON JWS, each parsed and verified under the RFC 7515 A.1 HS256, A.2
//! RS256 and A.3 ES256 keys.
use jose::{Error, ErrorKind, Es256, Hs256, Jwk, Jws, Rs256, SecretJwk};

const HS256: &[u8] = br#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#;
const RS256: &[u8] = br#"{"kty":"RSA","n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ","e":"AQAB"}"#;
const ES256: &[u8] = br#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;

/// Ok when any of the three keys verifies, else the HS256 key's refusal.
fn verify<'a>(parse: &dyn Fn() -> Result<Jws<'a>, Error>) -> Result<(), Error> {
    let hs = SecretJwk::decode(HS256)?.verify_key::<Hs256>()?;
    let rs = Jwk::decode(RS256)?.verify_key::<Rs256>()?;
    let es = Jwk::decode(ES256)?.verify_key::<Es256>()?;
    let others = [
        parse()?.verify(&rs).map(drop),
        parse()?.verify(&es).map(drop),
    ];
    parse()?.verify(&hs).map(drop).or_else(|refusal| {
        others
            .into_iter()
            .find(Result::is_ok)
            .unwrap_or(Err(refusal))
    })
}

/// The outcome of the serialization the first byte selects (`{` is JSON); both always run.
pub(crate) fn check(data: &[u8]) -> Result<(), ErrorKind> {
    let text = String::from_utf8_lossy(data);
    let compact = verify(&|| Jws::parse(&text));
    let json = verify(&|| Jws::parse_json(data));
    let outcome = if data.first() == Some(&b'{') {
        json
    } else {
        compact
    };
    outcome.map_err(|e| e.kind())
}
