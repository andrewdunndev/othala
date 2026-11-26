//! JWTs (RFC 7519 section 7.2): a compact JWS whose claims come out only through a policy.
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use base::UnixTime;

use crate::claims::check;
use crate::{Alg, AnyVerifyKey, Error, Jws, Kid, Policy, TokenKind, VerifyKey};

/// A parsed JWT, not verified; `Debug` prints only the `kid`.
pub struct Jwt<'a> {
    pub(crate) jws: Jws<'a>,
}

/// A JWT whose signature verified; its claims are reachable only through a [`crate::Policy`]. `Debug` prints its
/// `kid` only.
pub struct VerifiedJwt {
    pub(crate) kid: Option<Kid>,
    pub(crate) typ: Option<String>,
    pub(crate) cty: Option<String>,
    pub(crate) payload: Vec<u8>,
}

impl<'a> Jwt<'a> {
    /// Parses a compact JWS that is to hold claims.
    pub fn parse(compact: &'a str) -> Result<Self, Error> {
        Jws::parse(compact).map(|jws| Self { jws })
    }

    /// The `kid` the header names, as a hint only.
    pub fn kid(&self) -> Option<&Kid> {
        self.jws.kids().first()
    }

    /// Verifies the signature under `key`; the claims are not read.
    pub fn verify<A: Alg>(self, key: &VerifyKey<A>) -> Result<VerifiedJwt, Error> {
        let (payload, header) = self.jws.verify_parsed(key)?;
        Ok(VerifiedJwt {
            kid: header.kid,
            typ: header.typ,
            cty: header.cty,
            payload: payload.0,
        })
    }

    /// Verifies the signature under a key bound at runtime.
    pub fn verify_any(self, key: &AnyVerifyKey) -> Result<VerifiedJwt, Error> {
        let (payload, header) = self.jws.verify_any_parsed(key)?;
        Ok(VerifiedJwt {
            kid: header.kid,
            typ: header.typ,
            cty: header.cty,
            payload: payload.0,
        })
    }
}

impl VerifiedJwt {
    /// The claims, when they satisfy `policy` at `now`; the first failing check names the error.
    pub fn claims<K: TokenKind>(
        self,
        policy: &Policy<K>,
        now: UnixTime,
    ) -> Result<K::Claims, Error> {
        check(
            policy,
            now,
            self.typ.as_deref(),
            self.cty.as_deref(),
            &self.payload,
        )
    }
}

impl fmt::Debug for Jwt<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Jwt").field("kid", &self.kid()).finish()
    }
}

impl fmt::Debug for VerifiedJwt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedJwt")
            .field("kid", &self.kid)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned as _;
    use alloc::format;

    use base::SecretBytes;

    use super::Jwt;
    use crate::{Header, Hs256, Kid, SecretJwk, Unsigned};

    #[test]
    fn kid_and_debug() {
        let jwk = SecretJwk::from_oct(SecretBytes::new(alloc::vec![9; 32]));
        let (signer, verifier) = (
            jwk.signing_key::<Hs256>().ok(),
            jwk.verify_key::<Hs256>().ok(),
        );
        let header = Header::<Hs256>::new()
            .with_kid(Kid::new("the-kid").unwrap_or_else(|_| Kid(alloc::string::String::new())));
        let token = signer.and_then(|k| {
            Unsigned::<Hs256>::jws(header, b"{\"hidden\":1}")
                .ok()?
                .sign(&k)
                .ok()
        });
        let text = token
            .as_ref()
            .map(|t| t.as_str().to_owned())
            .unwrap_or_default();
        let jwt = Jwt::parse(&text).ok();
        assert_eq!(
            jwt.as_ref().and_then(Jwt::kid).map(Kid::as_str),
            Some("the-kid")
        );
        let shown = format!("{jwt:?}");
        assert!(
            shown.contains("the-kid") && !shown.contains(&text),
            "{shown}"
        );
        let verified = jwt.and_then(|j| verifier.and_then(|k| j.verify(&k).ok()));
        let shown = format!("{verified:?}");
        assert!(
            shown.contains("the-kid") && !shown.contains("hidden"),
            "{shown}"
        );
    }
}
