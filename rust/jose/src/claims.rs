//! JWT claims under a policy (RFC 7519 section 4.1, RFC 8725 sections 3.8 to 3.12).
use alloc::borrow::ToOwned as _;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use base::{UnixTime, b64url_encode};
use serde::de::IgnoredAny;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Number;
use sha2::{Digest as _, Sha256, Sha384, Sha512};

use crate::json::scan;
use crate::{Error, ErrorKind, MAX_LEEWAY, MAX_NAME_LEN, SigningAlg};

/// A kind of JWT: its `typ` and its claims. One per kind, so a policy never crosses kinds.
pub trait TokenKind {
    /// The `typ` this kind carries and requires.
    const TYP: Typ;
    /// The claims this kind yields, read strictly from the payload.
    type Claims: serde::de::DeserializeOwned;
}

/// A kind its own issuer may read back without being an audience, as an OP reads its `id_token_hint`
/// (OpenID Connect RP-Initiated Logout 1.0 section 2). Opt-in: only such a kind has `Policy::read_back`, and
/// only that policy takes [`Expiry::Unchecked`].
pub trait ReadBack: TokenKind {}

/// The `typ` header rule of a [`TokenKind`] (RFC 8725 sections 3.11 and 3.12).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Typ {
    /// Exactly this media type, compared case-insensitively with any `application/` prefix removed, e.g. `at+jwt`.
    Explicit(&'static str),
    /// `JWT` or absent: a kind that predates explicit typing, kept apart by its issuer, audience and claims.
    Generic,
}

/// The `exp` rule of a [`Policy`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expiry {
    /// `exp` must be present, numeric and after `now` minus the leeway; every `Policy::new` policy.
    Required,
    /// `exp`, when present, must be numeric; its time is not compared. Only `Policy::read_back` takes it.
    Unchecked,
}

/// What a JWT of kind `K` must satisfy before its claims are read. No `Default`; `Clone`, `Debug` and equality ask
/// nothing of `K`.
pub struct Policy<K: TokenKind> {
    pub(crate) issuer: Issuer,
    pub(crate) audience: Option<Audience>,
    pub(crate) leeway: Leeway,
    pub(crate) expiry: Expiry,
    pub(crate) kind: PhantomData<fn() -> K>,
}

/// An expected `iss`, compared byte for byte. A consumer's own URL rule wraps this type's constructor.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Issuer(pub(crate) String);

/// An expected `aud` entry, compared byte for byte.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Audience(pub(crate) String);

/// Clock leeway in seconds, at most [`crate::MAX_LEEWAY`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Leeway(pub(crate) u64);

//= https://www.rfc-editor.org/rfc/rfc7515#section-2
//= type=exception
//= reason=design choice: iss and aud are compared exactly with the host's, never parsed as URIs
//# StringOrURI A JSON string value, with the additional requirement that while arbitrary string
//# values MAY be used, any value containing a ":" character MUST be a URI [RFC3986].
//= https://www.rfc-editor.org/rfc/rfc7519#section-2
//= type=exception
//= reason=design choice: iss and aud are compared exactly with the host's, never parsed as URIs
//# StringOrURI A JSON string value, with the additional requirement that while arbitrary string
//# values MAY be used, any value containing a ":" character MUST be a URI [RFC3986].
fn name(text: &str) -> Result<String, Error> {
    if text.is_empty() {
        Err(ErrorKind::Malformed.into())
    } else if text.len() > MAX_NAME_LEN {
        Err(ErrorKind::TooLarge.into())
    } else {
        Ok(text.into())
    }
}

impl Issuer {
    /// An issuer: not empty (`Malformed`), at most `MAX_NAME_LEN` bytes (`TooLarge`).
    pub fn new(text: &str) -> Result<Self, Error> {
        name(text).map(Self)
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Audience {
    /// An audience: not empty (`Malformed`), at most `MAX_NAME_LEN` bytes (`TooLarge`).
    pub fn new(text: &str) -> Result<Self, Error> {
        name(text).map(Self)
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! text_serde {
    ($type:ty) => {
        impl Serialize for $type {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                Self::new(&String::deserialize(d)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

text_serde!(Issuer);
text_serde!(Audience);

impl Leeway {
    /// A leeway of `seconds`, at most `MAX_LEEWAY` (`TooLarge`).
    pub const fn new(seconds: u64) -> Result<Self, Error> {
        if seconds > MAX_LEEWAY {
            return Err(Error {
                kind: ErrorKind::TooLarge,
            });
        }
        Ok(Self(seconds))
    }

    /// The seconds.
    pub const fn seconds(self) -> u64 {
        self.0
    }
}

impl<K: TokenKind> Policy<K> {
    /// A policy that requires `exp` and an `aud` containing `audience`.
    pub fn new(issuer: Issuer, audience: Audience, leeway: Leeway) -> Result<Self, Error> {
        Ok(Self {
            issuer,
            audience: Some(audience),
            leeway,
            expiry: Expiry::Required,
            kind: PhantomData,
        })
    }
}

impl<K: ReadBack> Policy<K> {
    /// A policy for reading back a token this issuer made: `aud` must be well typed and is not compared, and `exp`
    /// is compared unless `expiry` is `Unchecked`.
    pub fn read_back(issuer: Issuer, leeway: Leeway, expiry: Expiry) -> Result<Self, Error> {
        Ok(Self {
            issuer,
            audience: None,
            leeway,
            expiry,
            kind: PhantomData,
        })
    }
}

impl<K: TokenKind> Clone for Policy<K> {
    fn clone(&self) -> Self {
        Self {
            issuer: self.issuer.clone(),
            audience: self.audience.clone(),
            leeway: self.leeway,
            expiry: self.expiry,
            kind: PhantomData,
        }
    }
}

impl<K: TokenKind> PartialEq for Policy<K> {
    fn eq(&self, other: &Self) -> bool {
        (&self.issuer, &self.audience, self.leeway, self.expiry)
            == (&other.issuer, &other.audience, other.leeway, other.expiry)
    }
}

impl<K: TokenKind> Eq for Policy<K> {}

impl<K: TokenKind> fmt::Debug for Policy<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Policy")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("leeway", &self.leeway)
            .field("expiry", &self.expiry)
            .finish()
    }
}

impl SigningAlg {
    /// The left half of the `alg`'s hash of `octets`, base64url (OpenID Connect Core 3.1.3.6, 3.3.2.11): SHA-256 for
    /// *256, SHA-384 for *384, SHA-512 for *512 and EdDSA.
    pub fn half_hash(self, octets: &[u8]) -> String {
        let hash: Vec<u8> = match self {
            Self::Hs256 | Self::Rs256 | Self::Ps256 | Self::Es256 => {
                Sha256::digest(octets).to_vec()
            }
            Self::Hs384 | Self::Rs384 | Self::Ps384 | Self::Es384 => {
                Sha384::digest(octets).to_vec()
            }
            _ => Sha512::digest(octets).to_vec(),
        };
        b64url_encode(hash.get(..hash.len() / 2).unwrap_or_default())
    }
}

/// A registered claim as the payload has it: absent, of the type wanted, or of another type (`null` included).
enum Claim<T> {
    Absent,
    Good(T),
    Wrong,
}

const fn absent<T>() -> Claim<T> {
    Claim::Absent
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Claim<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Typed<T> {
            Good(T),
            Wrong(IgnoredAny),
        }
        Ok(match Typed::<T>::deserialize(d)? {
            Typed::Good(value) => Self::Good(value),
            Typed::Wrong(_) => Self::Wrong,
        })
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audiences {
    One(String),
    Many(Vec<String>),
}

//= https://www.rfc-editor.org/rfc/rfc7519#section-4
//# However, in the absence of such requirements, all claims that are not understood by
//# implementations MUST be ignored.
//= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2
//= type=exception
//= reason=assigning sub values is the issuer's; jose reads no sub
//# The subject value MUST either be scoped to be locally unique in the context of the issuer or be
//# globally unique.
//= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7
//= type=exception
//= reason=assigning jti values is the issuer's; single use is the consumer's (O4)
//# The identifier value MUST be assigned in a manner that ensures that there is a negligible
//# probability that the same value will be accidentally assigned to a different data object; if the
//# application uses multiple issuers, collisions MUST be prevented among values produced by
//# different issuers as well.
//= https://www.rfc-editor.org/rfc/rfc7519#section-4
//= type=todo
//= reason=no test or vector carries a claim jose does not understand
//# However, in the absence of such requirements, all claims that are not understood by
//# implementations MUST be ignored.
#[derive(Deserialize)]
struct Registered {
    #[serde(default = "absent")]
    iss: Claim<String>,
    #[serde(default = "absent")]
    aud: Claim<Audiences>,
    #[serde(default = "absent")]
    exp: Claim<Number>,
    #[serde(default = "absent")]
    nbf: Claim<Number>,
    #[serde(default = "absent")]
    iat: Claim<Number>,
}

/// A JSON number as whole seconds, rounded down or up; an exponent form is a number like any other, and a value
/// outside `i64` is not a time.
fn seconds(number: &Number, up: bool) -> Option<i64> {
    if let Some(whole) = number.as_i64() {
        return Some(whole);
    }
    if number.is_u64() {
        return None;
    }
    // the float's own bits give the integer and fraction parts without a cast
    let bits = number.as_f64()?.to_bits();
    let negative = bits >> 63 == 1;
    let exponent = u32::try_from((bits >> 52) & 0x7ff).ok()?;
    let mantissa = (bits & ((1 << 52) - 1)) + (1 << 52);
    let (whole, part) = match exponent {
        ..1023 => (0, bits << 1 != 0),
        _ => match exponent - 1023 {
            shift @ 52..63 => (mantissa << (shift - 52), false),
            shift @ ..52 => {
                let dropped = 52 - shift;
                (mantissa >> dropped, mantissa & ((1 << dropped) - 1) != 0)
            }
            _ => return None,
        },
    };
    let whole = i64::try_from(whole).ok()?;
    match (part, up, negative) {
        (true, true, false) => whole.checked_add(1),
        (true, false, true) => Some(-whole).and_then(|n| n.checked_sub(1)),
        (_, _, true) => Some(-whole),
        _ => Some(whole),
    }
}

//= https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9
//# A recipient using the media type value MUST treat it as if "application/" were prepended to any
//# "typ" value not containing a '/'.
//= https://www.rfc-editor.org/rfc/rfc7515#section-4.1.10
//# A recipient using the media type value MUST treat it as if "application/" were prepended to any
//# "cty" value not containing a '/'.
/// Lower case, with an `application/` prefix removed (RFC 7515 4.1.9).
fn media_type(typ: &str) -> String {
    let lower = typ.to_ascii_lowercase();
    lower
        .strip_prefix("application/")
        .map_or(lower.clone(), str::to_owned)
}

//= https://www.rfc-editor.org/rfc/rfc7519#section-7.2
//# If any of the listed steps fail, then the JWT MUST be rejected -- that is, treated by the
//# application as an invalid input.
/// The checks of a [`Policy`] over a verified payload, in the order the contract names; the first failure is the
/// error.
pub(crate) fn check<K: TokenKind>(
    policy: &Policy<K>,
    now: UnixTime,
    typ: Option<&str>,
    cty: Option<&str>,
    payload: &[u8],
) -> Result<K::Claims, Error> {
    //= https://www.rfc-editor.org/rfc/rfc7519#section-4
    //# The Claim Names within a JWT Claims Set MUST be unique; JWT parsers MUST either reject JWTs
    //# with duplicate Claim Names or use a JSON parser that returns only the lexically last
    //# duplicate member name, as specified in Section 15.12 ("The JSON Object") of ECMAScript 5.1
    //# [ECMAScript].
    scan(payload)?;
    // the payload is a JSON object; RFC 8259 2 allows whitespace before it, and a struct would also read an array
    if payload.iter().find(|byte| !b" \t\n\r".contains(byte)) != Some(&b'{') {
        return Err(ErrorKind::Malformed.into());
    }
    let claims: Registered = serde_json::from_slice(payload).map_err(|_| ErrorKind::Malformed)?;
    let typ = typ.map(media_type);
    let typed = match K::TYP {
        Typ::Explicit(want) => typ.as_deref() == Some(media_type(want).as_str()),
        _ => typ.as_deref().is_none_or(|typ| typ == "jwt"),
    };
    if !typed {
        return Err(ErrorKind::Type.into());
    }
    if cty.is_some_and(|cty| media_type(cty) == "jwt") {
        return Err(ErrorKind::Malformed.into());
    }
    match &claims.iss {
        Claim::Absent => return Err(ErrorKind::MissingClaim.into()),
        Claim::Wrong => return Err(ErrorKind::ClaimType.into()),
        //= https://www.rfc-editor.org/rfc/rfc7519#section-7.3
        //# These comparison rules MUST be used for all JSON string comparisons except in cases
        //# where the definition of the member explicitly calls out that a different comparison rule
        //# is to be used for that member value.
        Claim::Good(iss) if *iss != policy.issuer.0 => return Err(ErrorKind::Issuer.into()),
        Claim::Good(_) => {}
    }
    //= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3
    //# Each principal intended to process the JWT MUST identify itself with a value in the audience
    //# claim.
    //= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3
    //# If the principal processing the claim does not identify itself with a value in the "aud"
    //# claim when this claim is present, then the JWT MUST be rejected.
    match (&claims.aud, &policy.audience) {
        (Claim::Absent, _) => return Err(ErrorKind::MissingClaim.into()),
        (Claim::Wrong, _) => return Err(ErrorKind::ClaimType.into()),
        (Claim::Good(aud), Some(want)) => {
            let found = match aud {
                Audiences::One(one) => *one == want.0,
                Audiences::Many(many) => many.contains(&want.0),
            };
            if !found {
                return Err(ErrorKind::Audience.into());
            }
        }
        //= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3
        //= type=deviation
        //= reason=R32 and O9: a read-back policy names no audience, so a foreign aud passes
        //# If the principal processing the claim does not identify itself with a value in the "aud"
        //# claim when this claim is present, then the JWT MUST be rejected.
        (Claim::Good(_), None) => {}
    }
    let (now, leeway) = (i128::from(now.secs()), i128::from(policy.leeway.0));
    //= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4
    //# The "exp" (expiration time) claim identifies the expiration time on or after which the JWT
    //# MUST NOT be accepted for processing.
    //= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4
    //# The processing of the "exp" claim requires that the current date/time MUST be before the
    //# expiration date/time listed in the "exp" claim.
    //= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4
    //# Its value MUST be a number containing a NumericDate value.
    match (&claims.exp, policy.expiry) {
        (Claim::Absent, Expiry::Required) => return Err(ErrorKind::MissingClaim.into()),
        (Claim::Wrong, _) => return Err(ErrorKind::ClaimType.into()),
        (Claim::Good(exp), Expiry::Required) => {
            let exp = seconds(exp, false).ok_or(ErrorKind::ClaimType)?;
            if i128::from(exp) <= now - leeway {
                return Err(ErrorKind::Expired.into());
            }
        }
        (Claim::Good(exp), _) => {
            seconds(exp, false).ok_or(ErrorKind::ClaimType)?;
        }
        (Claim::Absent, _) => {}
    }
    //= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5
    //# The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted
    //# for processing.
    //= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5
    //# The processing of the "nbf" claim requires that the current date/time MUST be after or equal
    //# to the not-before date/time listed in the "nbf" claim.
    //= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5
    //# Its value MUST be a number containing a NumericDate value.
    //= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6
    //# Its value MUST be a number containing a NumericDate value.
    for claim in [&claims.nbf, &claims.iat] {
        match claim {
            Claim::Wrong => return Err(ErrorKind::ClaimType.into()),
            Claim::Good(time) => {
                let time = seconds(time, true).ok_or(ErrorKind::ClaimType)?;
                if i128::from(time) > now + leeway {
                    return Err(ErrorKind::NotYetValid.into());
                }
            }
            Claim::Absent => {}
        }
    }
    serde_json::from_slice(payload).map_err(|_| ErrorKind::ClaimType.into())
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::String;
    use alloc::vec::Vec;

    use base::UnixTime;
    use serde::Deserialize;
    use sha2::{Digest as _, Sha256, Sha384, Sha512};

    use super::{Audience, Expiry, Issuer, Leeway, Policy, ReadBack, TokenKind, Typ, check};
    use crate::{ErrorKind, MAX_LEEWAY, MAX_NAME_LEN, SigningAlg};

    #[derive(Deserialize)]
    struct Anything {}

    struct Kind;
    struct Generic;

    impl TokenKind for Kind {
        const TYP: Typ = Typ::Explicit("at+jwt");
        type Claims = Anything;
    }

    impl TokenKind for Generic {
        const TYP: Typ = Typ::Generic;
        type Claims = Anything;
    }

    impl ReadBack for Generic {}

    const NOW: u64 = 1_000;

    fn policy() -> Policy<Kind> {
        Policy {
            issuer: Issuer(String::from("i")),
            audience: Some(Audience(String::from("a"))),
            leeway: Leeway(10),
            expiry: Expiry::Required,
            kind: core::marker::PhantomData,
        }
    }

    fn kind(payload: &str) -> Option<ErrorKind> {
        let run = check(
            &policy(),
            UnixTime::new(NOW),
            Some("at+jwt"),
            None,
            payload.as_bytes(),
        );
        run.err().map(|e| e.kind())
    }

    const GOOD: &str = r#""iss":"i","aud":"a","exp":2000"#;

    #[test]
    fn order() {
        assert_eq!(kind(&format!("{{{GOOD}}}")), None);
        assert_eq!(kind("[1]"), Some(ErrorKind::Malformed));
        assert_eq!(kind(&format!(" \t\r\n{{{GOOD}}}")), None);
        assert_eq!(kind(" \n[1]"), Some(ErrorKind::Malformed));
        assert_eq!(kind("\u{c}{}"), Some(ErrorKind::Malformed));
        assert_eq!(
            kind(r#"{"iss":"i","iss":"i"}"#),
            Some(ErrorKind::DuplicateMember)
        );
        // the earlier check wins over every later one
        let all_wrong = r#"{"iss":"x","aud":"x","exp":1,"nbf":9999,"iat":9999}"#;
        assert_eq!(kind(all_wrong), Some(ErrorKind::Issuer));
        assert_eq!(
            kind(r#"{"iss":"i","aud":"x","exp":1,"nbf":9999}"#),
            Some(ErrorKind::Audience)
        );
        assert_eq!(
            kind(r#"{"iss":"i","aud":"a","exp":1,"nbf":9999}"#),
            Some(ErrorKind::Expired)
        );
        assert_eq!(
            kind(r#"{"iss":"i","aud":"a","exp":2000,"nbf":9999,"iat":9999}"#),
            Some(ErrorKind::NotYetValid)
        );
        assert_eq!(
            kind(r#"{"iss":"i","aud":"a","exp":2000,"iat":9999}"#),
            Some(ErrorKind::NotYetValid)
        );
        assert_eq!(
            kind(r#"{"aud":"x","exp":"1"}"#),
            Some(ErrorKind::MissingClaim)
        );
        assert_eq!(
            kind(r#"{"iss":"i","aud":"a","exp":"1","nbf":"1"}"#),
            Some(ErrorKind::ClaimType)
        );
    }

    #[test]
    fn claim_types_and_values() {
        for (member, want) in [
            (r#""iss":5"#, ErrorKind::ClaimType),
            (r#""iss":null"#, ErrorKind::ClaimType),
            (r#""aud":5"#, ErrorKind::ClaimType),
            (r#""aud":["a",5]"#, ErrorKind::ClaimType),
            (r#""exp":"1""#, ErrorKind::ClaimType),
            (r#""exp":null"#, ErrorKind::ClaimType),
            (r#""nbf":"1""#, ErrorKind::ClaimType),
            (r#""iat":true"#, ErrorKind::ClaimType),
            (r#""nbf":1011"#, ErrorKind::NotYetValid),
            (r#""iat":1011"#, ErrorKind::NotYetValid),
            (r#""nbf":1010.5"#, ErrorKind::NotYetValid),
        ] {
            let name = member
                .split(':')
                .next()
                .unwrap_or_default()
                .trim_matches('"');
            let base: Vec<&str> = [r#""iss":"i""#, r#""aud":"a""#, r#""exp":2000"#]
                .into_iter()
                .filter(|m| !m.starts_with(&format!("\"{name}\"")))
                .collect();
            let payload = format!("{{{},{member}}}", base.join(","));
            assert_eq!(kind(&payload), Some(want), "{payload}");
        }
        for ok in [
            r#""aud":["x","a"]"#,
            r#""nbf":1010"#,
            r#""iat":1010"#,
            r#""nbf":1009.5"#,
            r#""exp":1010.5"#,
            r#""nbf":-5"#,
        ] {
            let name = ok.split(':').next().unwrap_or_default().trim_matches('"');
            let base: Vec<&str> = [r#""iss":"i""#, r#""aud":"a""#, r#""exp":2000"#]
                .into_iter()
                .filter(|m| !m.starts_with(&format!("\"{name}\"")))
                .collect();
            assert_eq!(kind(&format!("{{{},{ok}}}", base.join(","))), None, "{ok}");
        }
        assert_eq!(
            kind(r#"{"iss":"i","aud":"a","exp":990}"#),
            Some(ErrorKind::Expired)
        );
        assert_eq!(kind(r#"{"iss":"i","aud":"a","exp":991}"#), None);
        assert_eq!(
            kind(r#"{"iss":"i","aud":"a","exp":990.9}"#),
            Some(ErrorKind::Expired)
        );
        assert_eq!(
            kind(r#"{"iss":"i","aud":"a","exp":-990.5}"#),
            Some(ErrorKind::Expired)
        );
        assert_eq!(
            kind(r#"{"iss":"i","aud":"a"}"#),
            Some(ErrorKind::MissingClaim)
        );
    }

    //= https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9
    //= type=test
    //# A recipient using the media type value MUST treat it as if "application/" were prepended to
    //# any "typ" value not containing a '/'.
    //= https://www.rfc-editor.org/rfc/rfc7515#section-4.1.10
    //= type=test
    //# A recipient using the media type value MUST treat it as if "application/" were prepended to
    //# any "cty" value not containing a '/'.
    #[test]
    fn typ_and_cty() {
        let run = |typ: Option<&str>, cty: Option<&str>| {
            let payload = format!("{{{GOOD}}}");
            check(&policy(), UnixTime::new(NOW), typ, cty, payload.as_bytes())
                .err()
                .map(|e| e.kind())
        };
        assert_eq!(run(Some("AT+JWT"), None), None);
        assert_eq!(run(Some("application/at+jwt"), None), None);
        assert_eq!(run(Some("application/AT+jwt"), None), None);
        assert_eq!(run(Some("JWT"), None), Some(ErrorKind::Type));
        assert_eq!(run(None, None), Some(ErrorKind::Type));
        assert_eq!(run(Some("at+jwt"), Some("JWT")), Some(ErrorKind::Malformed));
        assert_eq!(
            run(Some("at+jwt"), Some("application/jwt")),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(run(Some("at+jwt"), Some("other")), None);
        let generic = |typ: Option<&str>| {
            let made = Policy::<Generic>::new(
                Issuer(String::from("i")),
                Audience(String::from("a")),
                Leeway(10),
            );
            let payload = format!("{{{GOOD}}}");
            let made = made.ok();
            made.map(|p| {
                check(&p, UnixTime::new(NOW), typ, None, payload.as_bytes())
                    .err()
                    .map(|e| e.kind())
            })
        };
        assert_eq!(generic(None), Some(None));
        assert_eq!(generic(Some("jwt")), Some(None));
        assert_eq!(generic(Some("at+jwt")), Some(Some(ErrorKind::Type)));
    }

    #[test]
    fn read_back_policy() {
        let read = |expiry, payload: &str| {
            let made =
                Policy::<Generic>::read_back(Issuer(String::from("i")), Leeway(10), expiry).ok();
            made.map(|p| {
                check(&p, UnixTime::new(NOW), None, None, payload.as_bytes())
                    .err()
                    .map(|e| e.kind())
            })
        };
        assert_eq!(
            read(Expiry::Unchecked, r#"{"iss":"i","aud":"x"}"#),
            Some(None)
        );
        assert_eq!(
            read(Expiry::Unchecked, r#"{"iss":"i","aud":"x","exp":1}"#),
            Some(None)
        );
        assert_eq!(
            read(Expiry::Unchecked, r#"{"iss":"i","aud":"x","exp":"1"}"#),
            Some(Some(ErrorKind::ClaimType))
        );
        assert_eq!(
            read(Expiry::Unchecked, r#"{"iss":"i"}"#),
            Some(Some(ErrorKind::MissingClaim))
        );
        assert_eq!(
            read(Expiry::Unchecked, r#"{"iss":"i","aud":7}"#),
            Some(Some(ErrorKind::ClaimType))
        );
        assert_eq!(
            read(Expiry::Required, r#"{"iss":"i","aud":"x","exp":1}"#),
            Some(Some(ErrorKind::Expired))
        );
        assert_eq!(
            read(Expiry::Required, r#"{"iss":"i","aud":"x"}"#),
            Some(Some(ErrorKind::MissingClaim))
        );
    }

    #[test]
    fn claims_must_deserialize() {
        #[derive(Deserialize)]
        struct Needs {
            #[expect(dead_code, reason = "read by the deserializer")]
            sub: String,
        }
        struct Strict;
        impl TokenKind for Strict {
            const TYP: Typ = Typ::Generic;
            type Claims = Needs;
        }
        let made = Policy::<Strict>::new(
            Issuer(String::from("i")),
            Audience(String::from("a")),
            Leeway(10),
        )
        .ok();
        let payload = format!("{{{GOOD}}}");
        let run = made.map(|p| {
            check(&p, UnixTime::new(NOW), None, None, payload.as_bytes())
                .err()
                .map(|e| e.kind())
        });
        assert_eq!(run, Some(Some(ErrorKind::ClaimType)));
    }

    #[test]
    fn name_bounds() {
        assert_eq!(
            Issuer::new("").err().map(|e| e.kind()),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            Audience::new("").err().map(|e| e.kind()),
            Some(ErrorKind::Malformed)
        );
        let longest = "x".repeat(MAX_NAME_LEN);
        let too_long = "x".repeat(MAX_NAME_LEN + 1);
        assert_eq!(
            Issuer::new(&longest).map(|i| i.as_str().len()).ok(),
            Some(MAX_NAME_LEN)
        );
        assert_eq!(
            Audience::new(&longest).map(|a| a.as_str().len()).ok(),
            Some(MAX_NAME_LEN)
        );
        assert_eq!(
            Issuer::new(&too_long).err().map(|e| e.kind()),
            Some(ErrorKind::TooLarge)
        );
        assert_eq!(
            Audience::new(&too_long).err().map(|e| e.kind()),
            Some(ErrorKind::TooLarge)
        );
        assert_eq!(
            serde_json::from_str::<Issuer>("\"x\"").ok(),
            Issuer::new("x").ok()
        );
        assert_eq!(
            serde_json::from_str::<Audience>("\"x\"").ok(),
            Audience::new("x").ok()
        );
        assert_eq!(
            (
                serde_json::from_str::<Issuer>("\"\"")
                    .err()
                    .map(|e| format!("{e}")),
                serde_json::from_str::<Audience>("\"\"")
                    .err()
                    .map(|e| format!("{e}")),
            ),
            (
                Some("input is not well-formed; reject it, it cannot be repaired".into()),
                Some("input is not well-formed; reject it, it cannot be repaired".into())
            )
        );
        assert_eq!(
            serde_json::to_string(&Issuer::new("x").ok())
                .ok()
                .as_deref(),
            Some("\"x\"")
        );
        assert_eq!(
            serde_json::to_string(&Audience::new("y").ok())
                .ok()
                .as_deref(),
            Some("\"y\"")
        );
    }

    #[test]
    fn whole_seconds() {
        let number = |text: &str| serde_json::from_str::<serde_json::Number>(text).ok();
        let both = |text: &str| {
            number(text).map(|n| (super::seconds(&n, false), super::seconds(&n, true)))
        };
        assert_eq!(both("2"), Some((Some(2), Some(2))));
        assert_eq!(both("2.0"), Some((Some(2), Some(2))));
        assert_eq!(both("1.5"), Some((Some(1), Some(2))));
        assert_eq!(both("-1.5"), Some((Some(-2), Some(-1))));
        assert_eq!(both("-0.5"), Some((Some(-1), Some(0))));
        assert_eq!(both("-3"), Some((Some(-3), Some(-3))));
        assert_eq!(both("1e300"), Some((None, None)));
        assert_eq!(both("0.0"), Some((Some(0), Some(0))));
        assert_eq!(both("-0.0"), Some((Some(0), Some(0))));
        assert_eq!(both("3.5"), Some((Some(3), Some(4))));
        assert_eq!(both("-3.5"), Some((Some(-4), Some(-3))));
        assert_eq!(
            both("1e17"),
            Some((Some(100_000_000_000_000_000), Some(100_000_000_000_000_000)))
        );
        assert_eq!(
            both("-1e17"),
            Some((
                Some(-100_000_000_000_000_000),
                Some(-100_000_000_000_000_000)
            ))
        );
        assert_eq!(both("1e-9"), Some((Some(0), Some(1))));
        assert_eq!(
            both("2251799813685248.5"),
            Some((Some(2_251_799_813_685_248), Some(2_251_799_813_685_249)))
        );
        assert_eq!(both("1e3"), Some((Some(1000), Some(1000))));
        assert_eq!(both("1.5e3"), Some((Some(1500), Some(1500))));
        assert_eq!(both("-1.5e0"), Some((Some(-2), Some(-1))));
        assert_eq!(both("18446744073709551615"), Some((None, None)));
        assert_eq!(
            both("9223372036854775807"),
            Some((Some(i64::MAX), Some(i64::MAX)))
        );
        assert_eq!(both("9223372036854775808.0"), Some((None, None)));
        assert_eq!(
            both("-9223372036854775808"),
            Some((Some(i64::MIN), Some(i64::MIN)))
        );
    }

    #[test]
    fn leeway_bound() {
        assert_eq!(
            Leeway::new(MAX_LEEWAY).map(Leeway::seconds).ok(),
            Some(MAX_LEEWAY)
        );
        assert_eq!(
            Leeway::new(MAX_LEEWAY + 1).err().map(|e| e.kind()),
            Some(ErrorKind::TooLarge)
        );
    }

    #[test]
    fn policies_compare_and_print() {
        let (a, b) = (policy(), policy());
        assert!(a == b && a.clone() == b);
        let other = Policy::<Kind>::new(
            Issuer(String::from("j")),
            Audience(String::from("a")),
            Leeway(10),
        )
        .ok();
        assert!(other.is_some_and(|o| o != a));
        let other = Policy::<Kind>::new(
            Issuer(String::from("i")),
            Audience(String::from("b")),
            Leeway(10),
        )
        .ok();
        assert!(other.is_some_and(|o| o != a));
        let other = Policy::<Kind>::new(
            Issuer(String::from("i")),
            Audience(String::from("a")),
            Leeway(11),
        )
        .ok();
        assert!(other.is_some_and(|o| o != a));
        let read =
            Policy::<Generic>::read_back(Issuer(String::from("i")), Leeway(10), Expiry::Required)
                .ok();
        let other =
            Policy::<Generic>::read_back(Issuer(String::from("i")), Leeway(10), Expiry::Unchecked)
                .ok();
        assert!(read != other);
        let shown = format!("{a:?}");
        assert!(
            shown.contains("Policy")
                && shown.contains("issuer")
                && shown.contains("leeway")
                && shown.contains("Required")
        );
    }

    #[test]
    fn half_hash() {
        let octets = b"an access token";
        let encode =
            |hash: &[u8]| base::b64url_encode(hash.get(..hash.len() / 2).unwrap_or_default());
        let want = [
            (
                encode(&Sha256::digest(octets)),
                [
                    SigningAlg::Hs256,
                    SigningAlg::Rs256,
                    SigningAlg::Ps256,
                    SigningAlg::Es256,
                ],
            ),
            (
                encode(&Sha384::digest(octets)),
                [
                    SigningAlg::Hs384,
                    SigningAlg::Rs384,
                    SigningAlg::Ps384,
                    SigningAlg::Es384,
                ],
            ),
            (
                encode(&Sha512::digest(octets)),
                [
                    SigningAlg::Hs512,
                    SigningAlg::Rs512,
                    SigningAlg::Ps512,
                    SigningAlg::Es512,
                ],
            ),
        ];
        for (hash, algs) in want {
            for alg in algs {
                assert_eq!(alg.half_hash(octets), hash, "{}", alg.name());
            }
        }
        assert_eq!(
            SigningAlg::EdDsa.half_hash(octets),
            encode(&Sha512::digest(octets))
        );
        assert_eq!(SigningAlg::Hs256.half_hash(octets).len(), 22);
        assert_eq!(SigningAlg::Hs384.half_hash(octets).len(), 32);
        assert_eq!(SigningAlg::Hs512.half_hash(octets).len(), 43);
    }
}
