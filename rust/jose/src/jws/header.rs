//! The JOSE header a JWS carries (RFC 7515 section 4): the duplicate pre-scan, `crit`, and the `alg` comparison.
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use base::b64url_decode;
use serde::Deserialize;
use serde::de::IgnoredAny;

use crate::crit::refuse_crit;
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

//= https://www.rfc-editor.org/rfc/rfc7515#section-4.1.2
//= type=exception
//= reason=non-goal N8: jose fetches nothing and never reads jku, x5u or x5c
//# The keys MUST be encoded as a JWK Set [JWK].
//= https://www.rfc-editor.org/rfc/rfc7515#section-4.1.2
//= type=exception
//= reason=non-goal N8: jose fetches nothing and never reads jku, x5u or x5c
//# The protocol used to acquire the resource MUST provide integrity protection; an HTTP GET request
//# to retrieve the JWK Set MUST use Transport Layer Security (TLS) [RFC2818] [RFC5246]; and the
//# identity of the server MUST be validated, as per Section 6 of RFC 6125 [RFC6125].
//= https://www.rfc-editor.org/rfc/rfc7515#section-4.1.5
//= type=exception
//= reason=non-goal N8: jose fetches nothing and never reads jku, x5u or x5c
//# The identified resource MUST provide a representation of the certificate or certificate chain
//# that conforms to RFC 5280 [RFC5280] in PEM-encoded form, with each certificate delimited as
//# specified in Section 6.1 of RFC 4945 [RFC4945].
//= https://www.rfc-editor.org/rfc/rfc7515#section-4.1.5
//= type=exception
//= reason=non-goal N8: jose fetches nothing and never reads jku, x5u or x5c
//# The certificate containing the public key corresponding to the key used to digitally sign the
//# JWS MUST be the first certificate.
//= https://www.rfc-editor.org/rfc/rfc7515#section-4.1.5
//= type=exception
//= reason=non-goal N8: jose fetches nothing and never reads jku, x5u or x5c
//# The protocol used to acquire the resource MUST provide integrity protection; an HTTP GET request
//# to retrieve the certificate MUST use TLS [RFC2818] [RFC5246]; and the identity of the server
//# MUST be validated, as per Section 6 of RFC 6125 [RFC6125].
//= https://www.rfc-editor.org/rfc/rfc7515#section-4.1.6
//= type=exception
//= reason=non-goal N8: jose fetches nothing and never reads jku, x5u or x5c
//# The certificate containing the public key corresponding to the key used to digitally sign the
//# JWS MUST be the first certificate.
//= https://www.rfc-editor.org/rfc/rfc7515#section-4.1.6
//= type=exception
//= reason=non-goal N8: jose fetches nothing and never reads jku, x5u or x5c
//# The recipient MUST validate the certificate chain according to RFC 5280 [RFC5280] and consider
//# the certificate or certificate chain to be invalid if any validation failure occurs.
//= https://www.rfc-editor.org/rfc/rfc7515#section-8
//= type=exception
//= reason=non-goal N8: jose fetches nothing and never reads jku, x5u or x5c
//# Implementations supporting the "jku" and/or "x5u" Header Parameters MUST support TLS.
//= https://www.rfc-editor.org/rfc/rfc7515#section-8
//= type=exception
//= reason=non-goal N8: jose fetches nothing and never reads jku, x5u or x5c
//# To protect against information disclosure and tampering, confidentiality protection MUST be
//# applied using TLS with a ciphersuite that provides confidentiality and integrity protection.
//= https://www.rfc-editor.org/rfc/rfc7515#section-8
//= type=exception
//= reason=non-goal N8: jose fetches nothing and never reads jku, x5u or x5c
//# Whenever TLS is used, the identity of the service provider encoded in the TLS server certificate
//# MUST be verified using the procedures described in Section 6 of RFC 6125 [RFC6125].
//= https://www.rfc-editor.org/rfc/rfc7515#section-4
//# All other Header Parameters defined by this specification that are not so designated MUST be
//# ignored when not understood.
//= https://www.rfc-editor.org/rfc/rfc7515#section-4
//# Unless listed as a critical Header Parameter, per Section 4.1.11, all Header Parameters not
//# defined by this specification MUST be ignored when not understood.
#[derive(Default, Deserialize)]
struct Fields {
    alg: Option<String>,
    //= https://www.rfc-editor.org/rfc/rfc7515#section-4.1.4
    //# Its value MUST be a case-sensitive string.
    kid: Option<String>,
    typ: Option<String>,
    cty: Option<String>,
    #[serde(default, deserialize_with = "named")]
    crit: Option<Vec<String>>,
    #[serde(default, deserialize_with = "named")]
    b64: Option<IgnoredAny>,
}

//= https://www.rfc-editor.org/rfc/rfc7515#section-4
//# The Header Parameter names within the JOSE Header MUST be unique; JWS parsers MUST either reject
//# JWSs with duplicate Header Parameter names or use a JSON parser that returns only the lexically
//# last duplicate member name, as specified in Section 15.12 ("The JSON Object") of ECMAScript 5.1
//# [ECMAScript].
//= https://www.rfc-editor.org/rfc/rfc7515#section-10.12
//# The Header Parameter names within the JOSE Header MUST be unique; JWS parsers MUST either reject
//# JWSs with duplicate Header Parameter names or use a JSON parser that returns only the lexically
//# last duplicate member name, as specified in Section 15.12 ("The JSON Object") of ECMAScript 5.1
//# [ECMAScript].
//= https://www.rfc-editor.org/rfc/rfc7515#section-10.12
//# Thus, this specification requires that the "SHOULD" in Section 4 of [RFC7159] be treated as a
//# "MUST" by producers and that it be either treated as a "MUST" or treated in the manner specified
//# in ECMAScript 5.1 by consumers.
//= https://www.rfc-editor.org/rfc/rfc7515#section-10.12
//# In particular, any JSON inputs not conforming to the JSON-text syntax defined in RFC 7159 MUST
//# be rejected in their entirety by JSON parsers.
//= https://www.rfc-editor.org/rfc/rfc7515#section-10.12
//# Implementations MUST consider JWSs containing such input to be invalid.
//= https://www.rfc-editor.org/rfc/rfc7515#section-10.12
//= type=todo
//= reason=no test parses a header with characters after its JSON object
//# Implementations MUST consider JWSs containing such input to be invalid.
//= https://www.rfc-editor.org/rfc/rfc7515#section-10.13
//= type=todo
//= reason=no test compares a name escaped outside the Basic Multilingual Plane
//# Ideally, JWS implementations SHOULD ensure that characters outside the Basic Multilingual Plane
//# are preserved and compared correctly; alternatively, if this is not possible due to these
//# characters exercising limitations present in the underlying JSON implementation, then input
//# containing them MUST be rejected.
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
        //= https://www.rfc-editor.org/rfc/rfc7515#section-5.2
        //# When using the JWS JSON Serialization, this restriction includes that the same Header
        //# Parameter name also MUST NOT occur in distinct JSON object values that together comprise
        //# the JOSE Header.
        //= https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1
        //# The Header Parameter names in the two locations MUST be disjoint.
        if held.intersection(&other).next().is_some() {
            return Err(ErrorKind::DuplicateMember.into());
        }
        if first.b64.is_some() || second.b64.is_some() {
            return Err(ErrorKind::Malformed.into());
        }
        refuse_crit(first.crit.as_deref(), &held, second.crit.is_some())?;
        let kid = first.kid.or(second.kid);
        //= https://www.rfc-editor.org/rfc/rfc7515#section-4.1.1
        //# This Header Parameter MUST be present and MUST be understood and processed by
        //# implementations.
        //= https://www.rfc-editor.org/rfc/rfc7515#section-3.2
        //# In the JWS JSON Serialization, one or both of the JWS Protected Header and JWS
        //# Unprotected Header MUST be present.
        //= https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1
        //# At least one of the "protected" and "header" members MUST be present for each
        //# signature/MAC computation so that an "alg" Header Parameter value is conveyed.
        //= https://www.rfc-editor.org/rfc/rfc7515#section-3.2
        //= type=todo
        //= reason=no test parses a JSON serialization signature with neither protected nor header
        //# In the JWS JSON Serialization, one or both of the JWS Protected Header and JWS
        //# Unprotected Header MUST be present.
        //= https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1
        //= type=todo
        //= reason=no test parses a JSON serialization signature with neither protected nor header
        //# At least one of the "protected" and "header" members MUST be present for each
        //# signature/MAC computation so that an "alg" Header Parameter value is conveyed.
        let alg = first.alg.or(second.alg).ok_or(ErrorKind::Malformed)?;
        Ok(Self {
            alg: Some(alg),
            //= https://www.rfc-editor.org/rfc/rfc7515#section-6
            //# These Header Parameters MUST be integrity protected if the information that they
            //# convey is to be utilized in a trust decision; however, if the only information used
            //# in the trust decision is a key, these parameters need not be integrity protected,
            //# since changing them in a way that causes a different key to be used will cause the
            //# validation to fail.
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
