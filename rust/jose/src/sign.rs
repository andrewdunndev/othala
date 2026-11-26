//! Issuing: the protected header, the signing input handed to a signer, and the compact token.
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use base::b64url_encode;

use crate::alg::sealed;
use crate::key::Private;
use crate::{
    Alg, Error, ErrorKind, Kid, LocalAlg, MAX_COMPACT_LEN, MAX_RSA_BITS, MIN_RSA_BITS, SignAlg,
    Signer, SigningAlg, TokenKind, Typ,
};

/// The protected header of a JWS this crate issues: `alg` is `A`'s, so it is never `none`; `kid` when given, and
/// `typ` when issued as a JWT.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header<A: Alg> {
    pub(crate) kid: Option<Kid>,
    pub(crate) typ: Option<&'static str>,
    pub(crate) alg: PhantomData<A>,
}

/// A JWS awaiting its `A` signature: the signing input goes to a signer (WebCrypto, a KMS, a [`crate::Signer`]),
/// and the signature comes back. This is the one effect the crate hands a host. `Debug` prints the header only.
#[must_use]
pub struct Unsigned<A: Alg> {
    pub(crate) header: Header<A>,
    pub(crate) input: Vec<u8>,
}

/// A compact JWS or JWE this crate produced. A bearer value: no `Display`, no equality, `Debug` prints its length
/// only.
#[derive(Clone)]
pub struct Compact(pub(crate) String);

/// A private or symmetric key that signs `A`. Not `Clone`, not `Serialize`, `Debug` redacted.
pub struct SigningKey<A: SignAlg> {
    pub(crate) material: Private,
    pub(crate) alg: PhantomData<A>,
}

impl<A: Alg> Header<A> {
    /// A header with `alg` `A`'s and nothing else.
    pub const fn new() -> Self {
        Self {
            kid: None,
            typ: None,
            alg: PhantomData,
        }
    }

    /// The same header with a `kid`.
    #[must_use]
    pub fn with_kid(self, kid: Kid) -> Self {
        Self {
            kid: Some(kid),
            ..self
        }
    }

    /// The `kid`, when set.
    pub const fn kid(&self) -> Option<&Kid> {
        self.kid.as_ref()
    }

    /// `A`'s algorithm.
    pub const fn alg(&self) -> SigningAlg {
        A::ALG
    }

    /// `{"alg":..,"kid":..,"typ":..}` without whitespace, `kid` JSON-escaped.
    fn json(&self) -> String {
        let mut json = alloc::format!(r#"{{"alg":"{}""#, A::ALG.name());
        if let Some(kid) = &self.kid {
            json.push_str(r#","kid":"#);
            json.push_str(&serde_json::to_string(kid.as_str()).unwrap_or_default());
        }
        if let Some(typ) = self.typ {
            json.push_str(r#","typ":""#);
            json.push_str(typ);
            json.push('"');
        }
        json.push('}');
        json
    }
}

impl<A: Alg> Default for Header<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Alg> Unsigned<A> {
    /// A JWS over `payload` under `header`; the signing input is `BASE64URL(header) '.' BASE64URL(payload)`.
    pub fn jws(header: Header<A>, payload: &[u8]) -> Result<Self, Error> {
        let input = alloc::format!(
            "{}.{}",
            b64url_encode(header.json().as_bytes()),
            b64url_encode(payload)
        );
        if input.len() > MAX_COMPACT_LEN {
            return Err(ErrorKind::TooLarge.into());
        }
        Ok(Self {
            header,
            input: input.into_bytes(),
        })
    }

    /// A JWT whose payload is `claims`, a JSON object, and whose `typ` is `K`'s: `JWT` for `Typ::Generic`, else the
    /// explicit value, which must be non-empty, lower case, not `application/`-prefixed and not `jwt`.
    pub fn jwt<K: TokenKind>(header: Header<A>, claims: &K::Claims) -> Result<Self, Error>
    where
        K::Claims: serde::Serialize,
    {
        let typ = match K::TYP {
            Typ::Explicit(typ)
                if typ.is_empty()
                    || typ.chars().any(char::is_uppercase)
                    || typ.starts_with("application/")
                    || typ == "jwt" =>
            {
                return Err(ErrorKind::Type.into());
            }
            Typ::Explicit(typ) => typ,
            _ => "JWT",
        };
        let payload = serde_json::to_vec(claims).map_err(|_| ErrorKind::Malformed)?;
        if payload.first() != Some(&b'{') {
            return Err(ErrorKind::Malformed.into());
        }
        Self::jws(
            Header {
                typ: Some(typ),
                ..header
            },
            &payload,
        )
    }

    /// The header.
    pub const fn header(&self) -> &Header<A> {
        &self.header
    }

    /// The octets a signer signs.
    pub fn signing_input(&self) -> &[u8] {
        &self.input
    }

    /// The compact token for `signature`, the signer's output; an RS or PS signature that is not the length of a
    /// 2048 to 8192 bit modulus is `Malformed`, and a token past `MAX_COMPACT_LEN` is `TooLarge`.
    pub fn finish(self, signature: A::Signature) -> Result<Compact, Error> {
        let signature = signature.as_ref();
        let rsa = matches!(
            A::ALG,
            SigningAlg::Rs256
                | SigningAlg::Rs384
                | SigningAlg::Rs512
                | SigningAlg::Ps256
                | SigningAlg::Ps384
                | SigningAlg::Ps512
        );
        if rsa && !(MIN_RSA_BITS / 8..=MAX_RSA_BITS / 8).contains(&signature.len()) {
            return Err(ErrorKind::Malformed.into());
        }
        let mut token = String::from_utf8(self.input).map_err(|_| ErrorKind::Malformed)?;
        token.push('.');
        token.push_str(&b64url_encode(signature));
        if token.len() > MAX_COMPACT_LEN {
            return Err(ErrorKind::TooLarge.into());
        }
        Ok(Compact(token))
    }

    /// Signs with `signer` and finishes; the signer's `Error` is returned unchanged.
    pub fn sign(self, signer: &impl Signer<A>) -> Result<Compact, Error> {
        let signature = signer.sign(&self.input)?;
        self.finish(signature)
    }
}

impl<A: Alg> fmt::Debug for Unsigned<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Unsigned")
            .field("alg", &A::ALG)
            .field("kid", &self.header.kid)
            .finish()
    }
}

impl Compact {
    /// The token text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Compact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Compact")
            .field("len", &self.0.len())
            .finish()
    }
}

impl<A: LocalAlg> Signer<A> for SigningKey<A> {
    fn sign(&self, input: &[u8]) -> Result<A::Signature, Error> {
        <A as sealed::Local>::sign(&self.material, input)
    }
}

impl<A: SignAlg> fmt::Debug for SigningKey<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey").field("alg", &A::ALG).finish()
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::{String, ToString as _};
    use alloc::vec;

    use serde::{Deserialize, Serialize};

    use super::{Header, Unsigned};
    use crate::{
        EdDsa, Error, ErrorKind, Hs256, Kid, MAX_COMPACT_LEN, Ps256, Rs256, Signer, TokenKind, Typ,
    };

    fn text<A: crate::Alg>(header: &Header<A>) -> String {
        header.json()
    }

    #[test]
    fn header_bytes() {
        assert_eq!(text(&Header::<Hs256>::new()), r#"{"alg":"HS256"}"#);
        assert_eq!(text(&Header::<EdDsa>::default()), r#"{"alg":"EdDSA"}"#);
        let kid = Kid::new("a\"b\\c\u{e9}").ok();
        let with =
            Header::<Hs256>::new().with_kid(kid.clone().unwrap_or_else(|| Kid("".to_string())));
        assert_eq!(
            text(&with),
            "{\"alg\":\"HS256\",\"kid\":\"a\\\"b\\\\c\u{e9}\"}"
        );
        assert_eq!(with.kid(), kid.as_ref());
        assert_eq!(with.alg(), crate::SigningAlg::Hs256);
        let typed = Header::<Hs256> {
            typ: Some("JWT"),
            ..with
        };
        assert!(text(&typed).ends_with(r#","typ":"JWT"}"#));
    }

    #[derive(Serialize, Deserialize)]
    struct Claims {
        iss: String,
    }

    struct Generic;
    struct At;
    struct Empty;
    struct Upper;
    struct Prefixed;
    struct Lower;

    macro_rules! kind {
        ($name:ident, $typ:expr) => {
            impl TokenKind for $name {
                const TYP: Typ = $typ;
                type Claims = Claims;
            }
        };
    }
    kind!(Generic, Typ::Generic);
    kind!(At, Typ::Explicit("at+jwt"));
    kind!(Empty, Typ::Explicit(""));
    kind!(Upper, Typ::Explicit("At+JWT"));
    kind!(Prefixed, Typ::Explicit("application/at+jwt"));
    kind!(Lower, Typ::Explicit("jwt"));

    #[test]
    fn typ_from_kind() {
        let claims = Claims {
            iss: "joe".to_string(),
        };
        let header = |u: Result<Unsigned<Hs256>, Error>| {
            let u = u.ok()?;
            let input = String::from_utf8(u.signing_input().to_vec()).ok()?;
            let segment = input.split('.').next()?.to_string();
            String::from_utf8(base::b64url_decode(&segment).ok()?).ok()
        };
        let jwt = |kind: &str| -> Result<Unsigned<Hs256>, Error> {
            match kind {
                "generic" => Unsigned::jwt::<Generic>(Header::new(), &claims),
                "at" => Unsigned::jwt::<At>(Header::new(), &claims),
                "empty" => Unsigned::jwt::<Empty>(Header::new(), &claims),
                "upper" => Unsigned::jwt::<Upper>(Header::new(), &claims),
                "prefixed" => Unsigned::jwt::<Prefixed>(Header::new(), &claims),
                _ => Unsigned::jwt::<Lower>(Header::new(), &claims),
            }
        };
        assert_eq!(
            header(jwt("generic")).as_deref(),
            Some(r#"{"alg":"HS256","typ":"JWT"}"#)
        );
        assert_eq!(
            header(jwt("at")).as_deref(),
            Some(r#"{"alg":"HS256","typ":"at+jwt"}"#)
        );
        for refused in ["empty", "upper", "prefixed", "lower"] {
            assert_eq!(
                jwt(refused).err().map(|e| e.kind()),
                Some(ErrorKind::Type),
                "{refused}"
            );
        }
        let payload = |u: Result<Unsigned<Hs256>, Error>| {
            let input = String::from_utf8(u.ok()?.signing_input().to_vec()).ok()?;
            String::from_utf8(base::b64url_decode(input.split('.').nth(1)?).ok()?).ok()
        };
        assert_eq!(payload(jwt("generic")).as_deref(), Some(r#"{"iss":"joe"}"#));
        struct Scalar;
        impl TokenKind for Scalar {
            const TYP: Typ = Typ::Generic;
            type Claims = alloc::vec::Vec<u8>;
        }
        let not_object = Unsigned::<Hs256>::jwt::<Scalar>(Header::new(), &vec![1]);
        assert_eq!(
            not_object.err().map(|e| e.kind()),
            Some(ErrorKind::Malformed)
        );
    }

    #[test]
    fn finish_lengths() {
        let finish = |len: usize| {
            let unsigned = Unsigned::<Rs256>::jws(Header::new(), b"x").ok()?;
            unsigned
                .finish(vec![1; len])
                .map(|c| c.as_str().len())
                .map_err(|e| e.kind())
                .into()
        };
        let results: [Result<usize, ErrorKind>; 4] =
            [finish(255), finish(256), finish(1024), finish(1025)]
                .map(|r: Option<Result<usize, ErrorKind>>| r.unwrap_or(Err(ErrorKind::Signer)));
        assert_eq!(results[0], Err(ErrorKind::Malformed));
        assert!(results[1].is_ok() && results[2].is_ok());
        assert_eq!(results[3], Err(ErrorKind::Malformed));
        let ps = Unsigned::<Ps256>::jws(Header::new(), b"x").and_then(|u| u.finish(vec![1; 10]));
        assert_eq!(ps.err().map(|e| e.kind()), Some(ErrorKind::Malformed));
        let hs = Unsigned::<Hs256>::jws(Header::new(), b"x").and_then(|u| u.finish([1; 32]));
        assert_eq!(
            hs.map(|c| c
                .as_str()
                .ends_with("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"))
                .ok(),
            Some(true)
        );
    }

    #[test]
    fn token_length_is_bounded() {
        let fits = |payload: usize| {
            Unsigned::<Hs256>::jws(Header::new(), &vec![0; payload]).and_then(|u| u.finish([0; 32]))
        };
        // header 20 + '.' + payload + '.' + 43
        let longest = (MAX_COMPACT_LEN - 65) / 4 * 3;
        assert!(fits(longest).is_ok());
        assert_eq!(
            fits(12_239).map(|c| c.as_str().len()).ok(),
            Some(MAX_COMPACT_LEN)
        );
        let exact = Unsigned::<Hs256>::jws(Header::new(), &vec![0; 12_272]);
        assert_eq!(
            exact.map(|u| u.signing_input().len()).ok(),
            Some(MAX_COMPACT_LEN)
        );
        assert!(Unsigned::<Hs256>::jws(Header::new(), &vec![0; 12_273]).is_err());
        assert_eq!(
            fits(longest + 3).err().map(|e| e.kind()),
            Some(ErrorKind::TooLarge)
        );
        assert_eq!(
            Unsigned::<Hs256>::jws(Header::new(), &vec![0; MAX_COMPACT_LEN])
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::TooLarge)
        );
    }

    struct Failing;

    impl Signer<Hs256> for Failing {
        fn sign(&self, _: &[u8]) -> Result<[u8; 32], Error> {
            Err(ErrorKind::Signer.into())
        }
    }

    #[test]
    fn signer_errors_pass_through() {
        let signed = Unsigned::<Hs256>::jws(Header::new(), b"x").and_then(|u| u.sign(&Failing));
        assert_eq!(signed.err().map(|e| e.kind()), Some(ErrorKind::Signer));
    }

    #[test]
    fn debug_redacted() {
        let key = crate::SecretJwk::from_oct(base::SecretBytes::new(vec![7; 32]))
            .signing_key::<Hs256>()
            .ok();
        assert_eq!(format!("{key:?}"), "Some(SigningKey { alg: Hs256 })");
        let unsigned = Unsigned::<Hs256>::jws(Header::new(), b"secretpayload");
        let shown = format!("{unsigned:?}");
        assert!(
            shown.contains("Hs256") && !shown.contains("secret"),
            "{shown}"
        );
        let token = unsigned.and_then(|u| u.finish([0; 32])).ok();
        let shown = format!("{token:?}");
        assert!(shown.contains("len") && !shown.contains("eyJ"), "{shown}");
    }
}
