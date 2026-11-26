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
#[derive(Clone)]
pub(crate) struct Parsed {
    pub(crate) alg: Option<String>,
    pub(crate) kid: Option<Kid>,
    pub(crate) typ: Option<String>,
    pub(crate) cty: Option<String>,
}

/// Every header name a registry defines (RFC 7515 4.1, RFC 7516 4.1, RFC 7518 4, RFC 7797): `crit` may not name one.
pub(crate) const REGISTERED: [&str; 22] = [
    "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit", "b64",
    "enc", "zip", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c", "ppt",
];

#[derive(Default, Deserialize)]
struct Fields {
    alg: Option<String>,
    kid: Option<String>,
    typ: Option<String>,
    cty: Option<String>,
    crit: Option<Vec<String>>,
    b64: Option<IgnoredAny>,
}

/// A header object: its known members, and every name it holds.
fn read(json: &[u8]) -> Result<(Fields, BTreeMap<String, IgnoredAny>), Error> {
    scan(json)?;
    let fields = serde_json::from_slice(json).map_err(|_| ErrorKind::Malformed)?;
    let names = serde_json::from_slice(json).map_err(|_| ErrorKind::Malformed)?;
    Ok((fields, names))
}

impl Parsed {
    /// An `alg` that needs a feature that is off is `UnsupportedAlg` for a compact or sole-signature token; among
    /// several signatures it is skipped as not the key's `alg`.
    pub(crate) fn supported(&self) -> Result<(), Error> {
        #[cfg(not(feature = "es512"))]
        if self.alg.as_deref() == Some("ES512") {
            return Err(ErrorKind::UnsupportedAlg.into());
        }
        Ok(())
    }

    /// The header a protected segment of base64url text and an optional unprotected header object hold, merged. A name
    /// in both is `DuplicateMember`; `crit` and `b64` are refused; `typ` and `cty` are read from the protected header
    /// only. A string `kid` that is not a valid [`Kid`] is dropped: a `kid` is a hint and never refuses a token.
    /// `jwk`, `jku`, `x5u` and `x5c` are never read.
    pub(crate) fn parse(protected: &str, unprotected: Option<&str>) -> Result<Self, Error> {
        let (first, held) = match protected {
            "" => Default::default(),
            text => read(&b64url_decode(text).map_err(|_| ErrorKind::Malformed)?)?,
        };
        let (second, other) = unprotected
            .map(|text| read(text.as_bytes()))
            .transpose()?
            .unwrap_or_default();
        if held.keys().any(|name| other.contains_key(name)) {
            return Err(ErrorKind::DuplicateMember.into());
        }
        if first.b64.is_some() || second.b64.is_some() || second.crit.is_some() {
            return Err(ErrorKind::Malformed.into());
        }
        if let Some(crit) = &first.crit {
            let usable = !crit.is_empty()
                && crit
                    .iter()
                    .all(|name| !REGISTERED.contains(&name.as_str()) && held.contains_key(name));
            return Err(if usable {
                ErrorKind::CriticalHeader
            } else {
                ErrorKind::Malformed
            }
            .into());
        }
        let kid = first.kid.or(second.kid);
        let alg = first.alg.or(second.alg).ok_or(ErrorKind::Malformed)?;
        Ok(Self {
            alg: Some(alg),
            kid: kid.and_then(|kid| Kid::new(&kid).ok()),
            typ: first.typ,
            cty: first.cty,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use crate::{ErrorKind, SigningAlg};

    #[test]
    fn names() {
        let registry = [
            "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
            "ES256", "ES384", "ES512", "EdDSA",
        ];
        for name in registry {
            let alg = SigningAlg::parse(name).ok();
            assert_eq!(alg.map(SigningAlg::name), Some(name));
            let json = alg.and_then(|alg| serde_json::to_string(&alg).ok());
            assert_eq!(json, Some(format!("\"{name}\"")));
            let back = json.and_then(|json| serde_json::from_str::<SigningAlg>(&json).ok());
            assert_eq!(back, alg);
            for changed in [name.to_ascii_lowercase(), name.to_ascii_uppercase()] {
                if changed != name {
                    assert_eq!(
                        SigningAlg::parse(&changed).err().map(|e| e.kind()),
                        Some(ErrorKind::UnsupportedAlg),
                        "{changed}"
                    );
                }
            }
        }
        for name in [
            "none",
            "RSA1_5",
            "PBES2-HS256+A128KW",
            "ES256K",
            "Ed25519",
            "DEF",
            "",
        ] {
            assert_eq!(
                SigningAlg::parse(name).err().map(|e| e.kind()),
                Some(ErrorKind::UnsupportedAlg),
                "{name}"
            );
            assert!(serde_json::from_str::<SigningAlg>(&format!("\"{name}\"")).is_err());
        }
    }
}
