//! The JOSE header a JWS carries (RFC 7515 section 4): the duplicate pre-scan, `crit`, and the `alg` comparison.
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use base::b64url_decode;
use serde::Deserialize;
use serde::de::IgnoredAny;

use crate::header::refuse_crit;
use crate::json::{named, scan};
use crate::{Error, ErrorKind, Kid};

/// One signature's protected and unprotected headers, merged after the duplicate check.
#[derive(Clone)]
pub(crate) struct Parsed {
    pub(crate) alg: Option<String>,
    pub(crate) kid: Option<Kid>,
    pub(crate) typ: Option<String>,
    pub(crate) cty: Option<String>,
}

#[derive(Default, Deserialize)]
struct Fields {
    alg: Option<String>,
    kid: Option<String>,
    typ: Option<String>,
    cty: Option<String>,
    #[serde(default, deserialize_with = "named")]
    crit: Option<Vec<String>>,
    #[serde(default, deserialize_with = "named")]
    b64: Option<IgnoredAny>,
}

/// A header object: its known members, and every name it holds.
fn read(json: &[u8]) -> Result<(Fields, BTreeSet<String>), Error> {
    scan(json)?;
    let fields = serde_json::from_slice(json).map_err(|_| ErrorKind::Malformed)?;
    let names: BTreeMap<String, IgnoredAny> =
        serde_json::from_slice(json).map_err(|_| ErrorKind::Malformed)?;
    Ok((fields, names.into_keys().collect()))
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
        if held.intersection(&other).next().is_some() {
            return Err(ErrorKind::DuplicateMember.into());
        }
        if first.b64.is_some() || second.b64.is_some() {
            return Err(ErrorKind::Malformed.into());
        }
        refuse_crit(first.crit.as_deref(), &held, second.crit.is_some())?;
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
            assert_eq!(
                serde_json::from_str::<SigningAlg>(&format!("\"{name}\""))
                    .err()
                    .map(|e| format!("{e}")),
                Some("algorithm, curve or compression is not supported; choose an implemented one or enable its feature".into()),
                "{name}"
            );
        }
    }
}
