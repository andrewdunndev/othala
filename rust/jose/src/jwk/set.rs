//! JWK Set decoding, lookup and publication (RFC 7517 section 5).
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use serde::ser::{SerializeMap as _, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::json::{object, scan};
use crate::jwk::decode::{Key, parse_filtered};
use crate::jwk::thumbprint::members;
use crate::{Error, ErrorKind, Jwk, Kid, MAX_JWKS_KEYS, SecretJwk};

/// A JWK Set: the public keys, and any private or symmetric ones a decoded document held, in document order.
/// `Serialize` writes the public keys only.
pub struct JwkSet {
    pub(crate) keys: Vec<Member>,
}

/// One kept key of a set.
pub(crate) enum Member {
    Public(Jwk),
    Secret(SecretJwk),
}

/// The key a `kid` names in a [`JwkSet`].
#[non_exhaustive]
#[derive(Clone, Copy)]
pub enum JwkEntry<'a> {
    /// A public key.
    Public(&'a Jwk),
    /// A private or symmetric key.
    Secret(&'a SecretJwk),
}

impl Member {
    fn kid(&self) -> Option<&Kid> {
        match self {
            Self::Public(key) => key.kid(),
            Self::Secret(key) => key.kid(),
        }
    }

    const fn entry(&self) -> JwkEntry<'_> {
        match self {
            Self::Public(key) => JwkEntry::Public(key),
            Self::Secret(key) => JwkEntry::Secret(key),
        }
    }
}

/// No `kid` twice (`DuplicateMember`), so a lookup by `kid` never has two answers.
fn distinct<'a>(kids: impl Iterator<Item = &'a Kid>) -> Result<(), Error> {
    let mut seen = BTreeSet::new();
    if kids.into_iter().all(|kid| seen.insert(kid)) {
        Ok(())
    } else {
        Err(ErrorKind::DuplicateMember.into())
    }
}

//= https://www.rfc-editor.org/rfc/rfc7517#section-5
//# Additional members can be present in the JWK Set; if not understood by implementations
//# encountering them, they MUST be ignored.
//= https://www.rfc-editor.org/rfc/rfc7517#section-5
//# The JSON object MUST have a "keys" member, with its value being an array of JWKs.
//= https://www.rfc-editor.org/rfc/rfc7517#section-2
//# The JSON object MUST have a "keys" member, which is an array of JWKs.
#[derive(Deserialize)]
struct Document<'a> {
    #[serde(borrow)]
    keys: Vec<&'a RawValue>,
}

impl JwkSet {
    /// Decodes `{"keys": [...]}`: a member object that is not a supported key (an unknown `kty`, a missing or
    /// out-of-range value, a weak modulus; RFC 7517 5) is skipped and not counted. A document without a `keys` array, a
    /// member that is not an object, a name used twice or more than `MAX_JWKS_KEYS` kept keys is refused. Members that
    /// share a `kid` are all skipped, since a lookup could not choose between them.
    /// For a document fetched from a remote `jwks_uri`, use [`Self::decode_public`].
    pub fn decode(json: &[u8]) -> Result<Self, Error> {
        Self::read(json, false)
    }

    /// As [`Self::decode`] for a document fetched from a remote `jwks_uri`: a key carrying any private parameter (`d`,
    /// `p`, `q`, `dp`, `dq`, `qi`), and any `oct` key, is dropped whole and not counted, so the set holds asymmetric
    /// public keys only and no secret an issuer published is ever a key.
    pub fn decode_public(json: &[u8]) -> Result<Self, Error> {
        Self::read(json, true)
    }

    //= https://www.rfc-editor.org/rfc/rfc7517#section-5
    //# The member names within a JWK Set MUST be unique; JWK Set parsers MUST either reject JWK
    //# Sets with duplicate member names or use a JSON parser that returns only the lexically last
    //# duplicate member name, as specified in Section 15.12 ("The JSON Object") of ECMAScript 5.1
    //# [ECMAScript].
    fn read(json: &[u8], public_only: bool) -> Result<Self, Error> {
        scan(json)?;
        let document: Document<'_> = object(json).map_err(|_| ErrorKind::Malformed)?;
        let mut keys = Vec::new();
        for raw in document.keys {
            if !raw.get().starts_with('{') {
                return Err(ErrorKind::Malformed.into());
            }
            match parse_filtered(raw.get().as_bytes(), public_only) {
                Ok(Some((meta, Key::Public(material)))) => {
                    keys.push(Member::Public(Jwk { meta, material }));
                }
                Ok(Some((meta, Key::Private(material)))) => {
                    keys.push(Member::Secret(SecretJwk { meta, material }));
                }
                Ok(None) | Err(_) => {}
            }
            // refused as soon as it is over, not after every member is parsed
            if keys.len() > MAX_JWKS_KEYS {
                return Err(ErrorKind::TooLarge.into());
            }
        }
        // `find` could not choose between members that share a `kid`, so none of them is kept (house rule, R27)
        let mut seen = BTreeSet::new();
        let shared: BTreeSet<Kid> = keys
            .iter()
            .filter_map(Member::kid)
            .filter(|kid| !seen.insert(*kid))
            .cloned()
            .collect();
        keys.retain(|key| key.kid().is_none_or(|kid| !shared.contains(kid)));
        Ok(Self { keys })
    }

    /// A set of public keys; more than `MAX_JWKS_KEYS` is `TooLarge`, a `kid` repeated `DuplicateMember`.
    pub fn new(keys: Vec<Jwk>) -> Result<Self, Error> {
        if keys.len() > MAX_JWKS_KEYS {
            return Err(ErrorKind::TooLarge.into());
        }
        distinct(keys.iter().filter_map(Jwk::kid))?;
        Ok(Self {
            keys: keys.into_iter().map(Member::Public).collect(),
        })
    }

    /// The key whose `kid` is `kid`, byte for byte, or none: an unknown `kid` is the host's cue to fetch the set
    /// again (OpenID Connect Core 10.1.1). A set never holds two keys with one `kid`, so a match is never a pick.
    pub fn find(&self, kid: &Kid) -> Option<JwkEntry<'_>> {
        self.keys
            .iter()
            .find(|key| key.kid() == Some(kid))
            .map(Member::entry)
    }

    /// The kept keys in document order.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = JwkEntry<'_>> {
        self.keys.iter().map(Member::entry)
    }
}

//= https://www.rfc-editor.org/rfc/rfc7517#section-4.9
//= type=exception
//= reason=x5u, x5c, x5t and x5t#S256 are ignored at decode and never written, so no certificate is read or matched; non-goal N9 (R30)
//# If other members are present, the contents of those members MUST be semantically consistent with
//# the related fields in the referenced certificate.
//= https://www.rfc-editor.org/rfc/rfc7517#section-4.9
//= type=exception
//= reason=x5u, x5c, x5t and x5t#S256 are ignored at decode and never written, so no certificate is read or matched; non-goal N9 (R30)
//# The key in the certificate MUST match the public key represented by other members of the JWK.
//= https://www.rfc-editor.org/rfc/rfc7517#section-4.8
//= type=exception
//= reason=x5u, x5c, x5t and x5t#S256 are ignored at decode and never written, so no certificate is read or matched; non-goal N9 (R30)
//# If other members are present, the contents of those members MUST be semantically consistent with
//# the related fields in the referenced certificate.
//= https://www.rfc-editor.org/rfc/rfc7517#section-4.8
//= type=exception
//= reason=x5u, x5c, x5t and x5t#S256 are ignored at decode and never written, so no certificate is read or matched; non-goal N9 (R30)
//# The key in the certificate MUST match the public key represented by other members of the JWK.
//= https://www.rfc-editor.org/rfc/rfc7517#section-4.7
//= type=exception
//= reason=x5u, x5c, x5t and x5t#S256 are ignored at decode and never written, so no certificate is read or matched; non-goal N9 (R30)
//# If other members are present, the contents of those members MUST be semantically consistent with
//# the related fields in the first certificate.
//= https://www.rfc-editor.org/rfc/rfc7517#section-4.7
//= type=exception
//= reason=x5u, x5c, x5t and x5t#S256 are ignored at decode and never written, so no certificate is read or matched; non-goal N9 (R30)
//# The key in the first certificate MUST match the public key represented by other members of the
//# JWK.
//= https://www.rfc-editor.org/rfc/rfc7517#section-4.7
//= type=exception
//= reason=x5u, x5c, x5t and x5t#S256 are ignored at decode and never written, so no certificate is read or matched; non-goal N9 (R30)
//# The PKIX certificate containing the key value MUST be the first certificate.
//= https://www.rfc-editor.org/rfc/rfc7517#section-4.6
//= type=exception
//= reason=x5u, x5c, x5t and x5t#S256 are ignored at decode and never written, so no certificate is read or matched; non-goal N9 (R30)
//# Similarly, if the "alg" member is present, it MUST correspond to the algorithm specified in the
//# certificate.
//= https://www.rfc-editor.org/rfc/rfc7517#section-4.6
//= type=exception
//= reason=x5u, x5c, x5t and x5t#S256 are ignored at decode and never written, so no certificate is read or matched; non-goal N9 (R30)
//# For instance, if the "use" member is present, then it MUST correspond to the usage that is
//# specified in the certificate, when it includes this information.
//= https://www.rfc-editor.org/rfc/rfc7517#section-4.6
//= type=exception
//= reason=x5u, x5c, x5t and x5t#S256 are ignored at decode and never written, so no certificate is read or matched; non-goal N9 (R30)
//# If other members are present, the contents of those members MUST be semantically consistent with
//# the related fields in the first certificate.
//= https://www.rfc-editor.org/rfc/rfc7517#section-4.6
//= type=exception
//= reason=x5u, x5c, x5t and x5t#S256 are ignored at decode and never written, so no certificate is read or matched; non-goal N9 (R30)
//# The protocol used to acquire the resource MUST provide integrity protection; an HTTP GET request
//# to retrieve the certificate MUST use TLS [RFC2818] [RFC5246]; the identity of the server MUST be
//# validated, as per Section 6 of RFC 6125 [RFC6125].
//= https://www.rfc-editor.org/rfc/rfc7517#section-4.6
//= type=exception
//= reason=x5u, x5c, x5t and x5t#S256 are ignored at decode and never written, so no certificate is read or matched; non-goal N9 (R30)
//# The key in the first certificate MUST match the public key represented by other members of the
//# JWK.
//= https://www.rfc-editor.org/rfc/rfc7517#section-4.6
//= type=exception
//= reason=x5u, x5c, x5t and x5t#S256 are ignored at decode and never written, so no certificate is read or matched; non-goal N9 (R30)
//# The identified resource MUST provide a representation of the certificate or certificate chain
//# that conforms to RFC 5280 [RFC5280] in PEM-encoded form, with each certificate delimited as
//# specified in Section 6.1 of RFC 4945 [RFC4945].
impl Serialize for Jwk {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        for (name, value) in members(&self.material) {
            map.serialize_entry(name, &value)?;
        }
        if let Some(kid) = &self.meta.kid {
            map.serialize_entry("kid", kid)?;
        }
        if let Some(alg) = self.meta.alg {
            map.serialize_entry("alg", alg)?;
        }
        if let Some(usage) = self.meta.use_name {
            map.serialize_entry("use", usage)?;
        }
        if !self.meta.ops.is_empty() {
            map.serialize_entry("key_ops", &self.meta.ops)?;
        }
        map.end()
    }
}

//= https://www.rfc-editor.org/rfc/rfc7517#section-9.2
//= type=exception
//= reason=storing and moving private and symmetric keys safely is the host's (O5, O11); jose's part is T16 (no Serialize) and R64 (Debug redaction)
//# Private and symmetric keys MUST be protected from disclosure to unintended parties.
//= https://www.rfc-editor.org/rfc/rfc7517#section-7
//= type=exception
//= reason=who may reach a non-public JWK is the host's (O5); jose's part is that SecretJwk is not Serialize (T16) and JwkSet writes public keys only (R30)
//# Access to JWKs containing non-public key material by parties without legitimate access to the
//# non-public information MUST be prevented.
impl Serialize for JwkSet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        let public = self.keys.iter().filter_map(|key| match key {
            Member::Public(key) => Some(key),
            Member::Secret(_) => None,
        });
        map.serialize_entry("keys", &public.collect::<Vec<_>>())?;
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned as _;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::JwkSet;
    use crate::{ErrorKind, JwkEntry, Kid, MAX_JWKS_KEYS};

    const K: &str = "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg";

    fn kids(text: &str) -> Result<Vec<String>, ErrorKind> {
        JwkSet::decode(text.as_bytes())
            .map(|set| {
                set.entries()
                    .filter_map(|entry| match entry {
                        JwkEntry::Public(key) => key.kid().map(|kid| kid.as_str().to_owned()),
                        JwkEntry::Secret(key) => key.kid().map(|kid| kid.as_str().to_owned()),
                    })
                    .collect()
            })
            .map_err(|e| e.kind())
    }

    fn set_text(text: &str) -> Result<usize, ErrorKind> {
        JwkSet::decode(text.as_bytes())
            .map(|s| s.entries().len())
            .map_err(|e| e.kind())
    }

    fn set(members: &[String]) -> Result<usize, ErrorKind> {
        let text = format!(r#"{{"keys":[{}]}}"#, members.join(","));
        JwkSet::decode(text.as_bytes())
            .map(|s| s.entries().len())
            .map_err(|e| e.kind())
    }

    fn oct(i: usize) -> String {
        format!(r#"{{"kty":"oct","kid":"k{i}","k":"{K}"}}"#)
    }

    #[test]
    fn a_key_with_a_null_member_is_skipped_and_an_array_is_no_object() {
        // a null member makes that key Malformed, and a Malformed key is skipped, not the whole set refused (R26)
        let nulled = oct_with("bad", r#""use":null"#);
        let text = format!(r#"{{"keys":[{nulled},{}]}}"#, oct(1));
        assert_eq!(kids(&text), Ok(vec!["k1".to_owned()]));
        assert_eq!(
            kids(&format!(r#"{{"keys":[{}]}}"#, oct(1))),
            Ok(vec!["k1".to_owned()])
        );
        // a set written as an array is not a set, however many members it holds
        let array = format!(r#"[[{}]]"#, oct(1));
        assert_eq!(kids(&array), Err(ErrorKind::Malformed));
    }

    fn oct_with(kid: &str, member: &str) -> String {
        format!(r#"{{"kty":"oct","kid":"{kid}","k":"{K}",{member}}}"#)
    }

    //= https://www.rfc-editor.org/rfc/rfc7517#section-4.3
    //= type=test
    //# The "use" and "key_ops" JWK members SHOULD NOT be used together; however, if both are used,
    //# the information they convey MUST be consistent.
    //= https://www.rfc-editor.org/rfc/rfc7517#section-4.3
    //= type=test
    //# Duplicate key operation values MUST NOT be present in the array.
    #[test]
    fn members_that_are_not_supported_keys_are_skipped() {
        let x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
        let members = [
            oct(0),
            r#"{"kty":"RSA","kid":"weak","n":"AQAB","e":"AQAB"}"#.to_owned(),
            r#"{"kty":"other","kid":"unknown-kty"}"#.to_owned(),
            r#"{"kty":"EC","kid":"no-y","crv":"P-256"}"#.to_owned(),
            r#"{"kty":"EC","kid":"short-coordinates","crv":"P-256","x":"AQ","y":"AQ"}"#.to_owned(),
            format!(r#"{{"kty":"OKP","kid":"x25519","crv":"X25519","x":"{x}"}}"#),
            oct_with("unknown-use", r#""use":"other""#),
            oct_with("unknown-op", r#""key_ops":["other"]"#),
            oct_with("repeated-op", r#""key_ops":["sign","sign"]"#),
            oct_with("disagree", r#""use":"enc","key_ops":["verify"]"#),
            oct_with("bad-alg", r#""alg":"none""#),
            r#"{"kty":"oct","kid":"bad-k","k":"!"}"#.to_owned(),
            format!(r#"{{"kty":"OKP","kid":"okp","crv":"Ed25519","x":"{x}"}}"#),
        ];
        let text = format!(r#"{{"keys":[{}]}}"#, members.join(","));
        assert_eq!(kids(&text), Ok(vec!["k0".to_owned(), "okp".to_owned()]));
        assert_eq!(set(&[]), Ok(0));
    }

    //= https://www.rfc-editor.org/rfc/rfc7517#section-5
    //= type=test
    //# The JSON object MUST have a "keys" member, with its value being an array of JWKs.
    //= https://www.rfc-editor.org/rfc/rfc7517#section-2
    //= type=test
    //# The JSON object MUST have a "keys" member, which is an array of JWKs.
    #[test]
    fn a_set_malformed_as_a_whole_is_refused() {
        let refused = |text: &str| kids(text).err();
        assert_eq!(refused(r#"{"kids":[]}"#), Some(ErrorKind::Malformed));
        assert_eq!(refused(r#"{"keys":{}}"#), Some(ErrorKind::Malformed));
        assert_eq!(refused(r#"[]"#), Some(ErrorKind::Malformed));
        for member in ["1", "null", r#""oct""#, "[]", "true"] {
            let text = format!(r#"{{"keys":[{},{member}]}}"#, oct(0));
            assert_eq!(refused(&text), Some(ErrorKind::Malformed), "{member}");
        }
        let named_twice = r#"{"keys":[{"kty":"oct","kty":"oct"}]}"#;
        assert_eq!(refused(named_twice), Some(ErrorKind::DuplicateMember));
        let skipped = format!(r#"{{"keys":[{0},{0}]}}"#, r#"{"kty":"other","kid":"k0"}"#);
        assert_eq!(kids(&skipped), Ok(Vec::new()));
    }

    #[test]
    fn members_that_share_a_kid_are_all_skipped() {
        let text = format!(
            r#"{{"keys":[{},{},{},{}]}}"#,
            oct(0),
            oct(1),
            oct(0),
            oct(0)
        );
        assert_eq!(kids(&text), Ok(vec!["k1".to_owned()]));
        let all = format!(r#"{{"keys":[{0},{0}]}}"#, oct(0));
        assert_eq!(kids(&all), Ok(Vec::new()));
        // a wrong-typed kid is a member that is skipped, not a refusal of the set
        let typed = format!(
            r#"{{"keys":[{},{{"kty":"oct","kid":5,"k":"{K}"}}]}}"#,
            oct(0)
        );
        assert_eq!(set_text(&typed), Ok(1));
        // a member skipped for another reason does not make a usable key's kid shared
        let other = r#"{"kty":"other","kid":"k0"}"#;
        let text = format!(r#"{{"keys":[{other},{},{}]}}"#, oct(0), oct(1));
        assert_eq!(kids(&text), Ok(vec!["k0".to_owned(), "k1".to_owned()]));
        let public = r#"{"kty":"OKP","kid":"k0","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
        let text = format!(r#"{{"keys":[{},{public}]}}"#, oct(0));
        let remote = JwkSet::decode_public(text.as_bytes()).map(|s| s.entries().len());
        assert_eq!(remote.map_err(|e| e.kind()), Ok(1));
    }

    #[test]
    fn find_is_some_for_a_kid_the_set_holds_and_none_otherwise() {
        let text = format!(r#"{{"keys":[{},{}]}}"#, oct(0), oct(1));
        let set = JwkSet::decode(text.as_bytes()).ok();
        let find = |kid: &str| {
            let kid = Kid::new(kid).ok()?;
            match set.as_ref()?.find(&kid)? {
                JwkEntry::Secret(key) => key.kid().map(|kid| kid.as_str().to_owned()),
                _ => None,
            }
        };
        assert_eq!(find("k1"), Some("k1".to_owned()));
        assert_eq!(find("k2"), None);
        assert_eq!(find("K1"), None);
    }

    #[test]
    fn remote_sets_keep_asymmetric_public_keys_only() {
        let private = r#"{"kty":"OKP","crv":"Ed25519","kid":"p","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#.to_owned();
        let public = r#"{"kty":"OKP","crv":"Ed25519","kid":"q","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#.to_owned();
        let text = format!(r#"{{"keys":[{},{},{}]}}"#, oct(0), private, public);
        let kept = |decode: fn(&[u8]) -> Result<JwkSet, crate::Error>| {
            decode(text.as_bytes()).map(|s| s.entries().len()).ok()
        };
        assert_eq!(kept(JwkSet::decode), Some(3));
        assert_eq!(kept(JwkSet::decode_public), Some(1));
        let many: Vec<String> = (0..=MAX_JWKS_KEYS).map(oct).collect();
        let text = format!(r#"{{"keys":[{}]}}"#, many.join(","));
        assert_eq!(
            JwkSet::decode_public(text.as_bytes())
                .map(|s| s.entries().len())
                .ok(),
            Some(0)
        );
    }

    #[test]
    fn key_count_is_refused_before_later_members_are_read() {
        let mut keys: Vec<String> = (0..=MAX_JWKS_KEYS).map(oct).collect();
        keys.push("1".to_owned());
        assert_eq!(set(&keys), Err(ErrorKind::TooLarge));
    }

    #[test]
    fn key_count_is_bounded() {
        let keys: Vec<String> = (0..=MAX_JWKS_KEYS).map(oct).collect();
        assert_eq!(
            set(keys.get(..MAX_JWKS_KEYS).unwrap_or_default()),
            Ok(MAX_JWKS_KEYS)
        );
        assert_eq!(set(&keys), Err(ErrorKind::TooLarge));
    }
}
