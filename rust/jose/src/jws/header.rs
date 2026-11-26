//! The JOSE header a JWS carries (RFC 7515 section 4): the duplicate pre-scan, `crit`, and the `alg` comparison.
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use base::b64url_decode;
use serde::Deserialize;
use serde::de::IgnoredAny;

use crate::jwk::decode::scan;
use crate::{Error, ErrorKind, Kid};

/// One signature's protected and unprotected headers, merged after the duplicate check.
pub(crate) struct Parsed {
    pub(crate) alg: Option<String>,
    pub(crate) kid: Option<Kid>,
    pub(crate) typ: Option<String>,
    pub(crate) cty: Option<String>,
}

/// Every header name a registry defines (RFC 7515 4.1, RFC 7516 4.1, RFC 7518 4, RFC 7797): `crit` may not name one.
const REGISTERED: [&str; 22] = [
    "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit", "b64",
    "enc", "zip", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c", "ppt",
];

#[derive(Deserialize)]
struct Fields {
    alg: String,
    kid: Option<String>,
    typ: Option<String>,
    cty: Option<String>,
    crit: Option<Vec<String>>,
    b64: Option<IgnoredAny>,
}

impl Parsed {
    /// The header a segment of base64url text holds. A string `kid` that is not a valid [`Kid`] is dropped: a `kid`
    /// is a hint and never refuses a token. `jwk`, `jku`, `x5u` and `x5c` are never read.
    pub(crate) fn parse(segment: &str) -> Result<Self, Error> {
        let json = b64url_decode(segment).map_err(|_| ErrorKind::Malformed)?;
        scan(&json)?;
        let fields: Fields = serde_json::from_slice(&json).map_err(|_| ErrorKind::Malformed)?;
        if fields.b64.is_some() {
            return Err(ErrorKind::Malformed.into());
        }
        if let Some(crit) = &fields.crit {
            let present: BTreeMap<String, IgnoredAny> =
                serde_json::from_slice(&json).map_err(|_| ErrorKind::Malformed)?;
            let usable = !crit.is_empty()
                && crit
                    .iter()
                    .all(|name| !REGISTERED.contains(&name.as_str()) && present.contains_key(name));
            return Err(if usable {
                ErrorKind::CriticalHeader
            } else {
                ErrorKind::Malformed
            }
            .into());
        }
        Ok(Self {
            alg: Some(fields.alg),
            kid: fields.kid.and_then(|kid| Kid::new(&kid).ok()),
            typ: fields.typ,
            cty: fields.cty,
        })
    }
}
