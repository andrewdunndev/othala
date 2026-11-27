//! `jwe_parse`: the input as compact and as JSON JWE, each parsed and decrypted as `dir` with A128GCM under the
//! RFC 7520 5.6 key.
use jose::{A128Gcm, Dir, ErrorKind, Jwe, SecretJwk};

const KEY: &[u8] = br#"{"kty":"oct","k":"XctOhJAkA-pD9Lh7ZgW_2A"}"#;

/// The outcome of the serialization the first byte selects (`{` is JSON); both always run.
pub(crate) fn check(data: &[u8]) -> Result<(), ErrorKind> {
    let key = SecretJwk::decode(KEY)
        .and_then(|k| k.decrypt_key::<Dir>())
        .map_err(|e| e.kind())?;
    let text = String::from_utf8_lossy(data);
    let compact = Jwe::parse(&text).and_then(|jwe| jwe.decrypt::<Dir, A128Gcm>(&key));
    let json = Jwe::parse_json(data).and_then(|jwe| jwe.decrypt::<Dir, A128Gcm>(&key));
    let outcome = if data.first() == Some(&b'{') {
        json
    } else {
        compact
    };
    outcome.map(drop).map_err(|e| e.kind())
}
