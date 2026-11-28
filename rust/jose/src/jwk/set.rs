//! JWK Set decoding, lookup and publication (RFC 7517 section 5).
use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use serde::ser::{SerializeMap as _, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::jwk::decode::{Key, parse_filtered, scan};
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

#[derive(Deserialize)]
struct Document<'a> {
    #[serde(borrow)]
    keys: Vec<&'a RawValue>,
}

impl JwkSet {
    /// Decodes `{"keys": [...]}`: a member object that is not a supported key (an unknown `kty`, a missing or
    /// out-of-range value, a weak modulus; RFC 7517 5) is skipped and not counted. A document without a `keys` array, a
    /// member that is not an object, a name used twice, a `kid` shared by two kept keys or more than `MAX_JWKS_KEYS`
    /// kept keys is refused.
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

    fn read(json: &[u8], public_only: bool) -> Result<Self, Error> {
        scan(json)?;
        let document: Document<'_> =
            serde_json::from_slice(json).map_err(|_| ErrorKind::Malformed)?;
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
        distinct(keys.iter().filter_map(Member::kid))?;
        Ok(Self { keys })
    }

    /// A set of public keys; more than `MAX_JWKS_KEYS` is `TooLarge`, a `kid` repeated `DuplicateMember`, as in [`Self::decode`].
    pub fn new(keys: Vec<Jwk>) -> Result<Self, Error> {
        if keys.len() > MAX_JWKS_KEYS {
            return Err(ErrorKind::TooLarge.into());
        }
        distinct(keys.iter().filter_map(Jwk::kid))?;
        Ok(Self {
            keys: keys.into_iter().map(Member::Public).collect(),
        })
    }

    /// The key whose `kid` is `kid`, byte for byte, or none: the host decides whether an unknown `kid` means fetching
    /// the set again (RFC 7517 4.5). A set never holds two keys with one `kid`, so a match is never a pick.
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

    fn set(members: &[String]) -> Result<usize, ErrorKind> {
        let text = format!(r#"{{"keys":[{}]}}"#, members.join(","));
        JwkSet::decode(text.as_bytes())
            .map(|s| s.entries().len())
            .map_err(|e| e.kind())
    }

    fn oct(i: usize) -> String {
        format!(r#"{{"kty":"oct","kid":"k{i}","k":"{K}"}}"#)
    }

    fn oct_with(kid: &str, member: &str) -> String {
        format!(r#"{{"kty":"oct","kid":"{kid}","k":"{K}",{member}}}"#)
    }

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
        let twice = format!(r#"{{"keys":[{},{}]}}"#, oct(0), oct(0));
        assert_eq!(refused(&twice), Some(ErrorKind::DuplicateMember));
        let named_twice = r#"{"keys":[{"kty":"oct","kty":"oct"}]}"#;
        assert_eq!(refused(named_twice), Some(ErrorKind::DuplicateMember));
        let skipped = format!(r#"{{"keys":[{0},{0}]}}"#, r#"{"kty":"other","kid":"k0"}"#);
        assert_eq!(kids(&skipped), Ok(Vec::new()));
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
