//! The JWS compact serialization (RFC 7515 section 7.1) and verification.
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use base::b64url_decode;

use crate::jws::header::Parsed;
use crate::key::dup;
use crate::{
    Alg, AnyVerifyKey, EdDsa, Error, ErrorKind, Es256, Es384, Kid, MAX_COMPACT_LEN, Ps256, Ps384,
    Ps512, Rs256, Rs384, Rs512, SigningAlg, VerifyKey,
};

/// One signature of a JWS: the protected header text as received, the merged header, the signature bytes.
pub(crate) struct Signature<'a> {
    pub(crate) protected: &'a str,
    pub(crate) header: Parsed,
    pub(crate) bytes: Vec<u8>,
}

/// A parsed JWS, not verified: no accessor reaches its payload, and `Debug` prints only the `kid`s.
pub struct Jws<'a> {
    pub(crate) payload: &'a str,
    pub(crate) signatures: Vec<Signature<'a>>,
    pub(crate) kids: Vec<Kid>,
}

/// A verified JWS payload: the signature holds, the content is not validated. `Debug` prints its length only.
pub struct Payload(pub(crate) Vec<u8>);

fn malformed() -> Error {
    ErrorKind::Malformed.into()
}

impl<'a> Jws<'a> {
    /// Parses a compact JWS: three canonical base64url segments, the first a JSON object header with an `alg`.
    pub fn parse(compact: &'a str) -> Result<Self, Error> {
        if compact.len() > MAX_COMPACT_LEN {
            return Err(ErrorKind::TooLarge.into());
        }
        let mut segments = compact.split('.');
        let (Some(protected), Some(payload), Some(signature), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return Err(malformed());
        };
        let header = Parsed::parse(protected, None)?;
        header.supported()?;
        b64url_decode(payload).map_err(|_| malformed())?;
        let bytes = b64url_decode(signature).map_err(|_| malformed())?;
        Ok(Self {
            payload,
            kids: header.kid.iter().cloned().collect(),
            signatures: vec![Signature {
                protected,
                header,
                bytes,
            }],
        })
    }

    /// The `kid`s the headers name, as hints only.
    pub fn kids(&self) -> &[Kid] {
        &self.kids
    }

    /// The payload, when a signature whose `alg` is `A`'s verifies under `key`: `AlgMismatch` when no signature names
    /// `A`, `BadSignature` when some do and none verifies. The header never selects an algorithm.
    pub fn verify<A: Alg>(self, key: &VerifyKey<A>) -> Result<Payload, Error> {
        self.verify_parsed(key).map(|(payload, _)| payload)
    }

    /// As [`Self::verify`], with the header of the signature that verified.
    pub(crate) fn verify_parsed<A: Alg>(
        self,
        key: &VerifyKey<A>,
    ) -> Result<(Payload, Parsed), Error> {
        let name = A::ALG.name();
        let mut named = false;
        for signature in &self.signatures {
            //= https://www.rfc-editor.org/rfc/rfc7515#section-5.2
            //# Validate the JWS Signature against the JWS Signing Input ASCII(BASE64URL(UTF8(JWS
            //# Protected Header)) || '.' || BASE64URL(JWS Payload)) in the manner defined for the
            //# algorithm being used, which MUST be accurately represented by the value of the "alg"
            //# (algorithm) Header Parameter, which MUST be present.
            //= https://www.rfc-editor.org/rfc/rfc7515#section-5.3
            //# These comparison rules MUST be used for all JSON string comparisons except in cases
            //# where the definition of the member explicitly calls out that a different comparison
            //# rule is to be used for that member value.
            //= https://www.rfc-editor.org/rfc/rfc7515#section-10.6
            //# When using such libraries, as part of the algorithm validation performed,
            //# implementations MUST ensure that the algorithm information encoded in the signature
            //# corresponds to that specified with the "alg" Header Parameter.
            if signature.header.alg.as_deref() != Some(name) {
                continue;
            }
            named = true;
            let input = [signature.protected, ".", self.payload].concat();
            if let Ok(()) = key.verify_signature(input.as_bytes(), &signature.bytes) {
                let payload = b64url_decode(self.payload)
                    .map(Payload)
                    .map_err(|_| malformed())?;
                return Ok((payload, signature.header.clone()));
            }
        }
        //= https://www.rfc-editor.org/rfc/rfc7515#section-5.2
        //# However, in all cases, at least one JWS Signature value MUST successfully validate, or
        //# the JWS MUST be considered invalid.
        //= https://www.rfc-editor.org/rfc/rfc7515#section-5.2
        //# If none of the validations in step 9 succeeded, then the JWS MUST be considered invalid.
        Err(if named {
            ErrorKind::BadSignature
        } else {
            ErrorKind::AlgMismatch
        }
        .into())
    }
}

impl<'a> Jws<'a> {
    /// Verifies under a key bound at runtime: the header `alg` is compared with the key's and never selects code.
    pub fn verify_any(self, key: &AnyVerifyKey) -> Result<Payload, Error> {
        self.verify_any_parsed(key).map(|(payload, _)| payload)
    }

    /// As [`Self::verify_any`], with the header of the signature that verified.
    pub(crate) fn verify_any_parsed(self, key: &AnyVerifyKey) -> Result<(Payload, Parsed), Error> {
        macro_rules! under {
            ($marker:ty) => {
                self.verify_parsed(&VerifyKey::<$marker> {
                    material: dup(&key.material),
                    alg: core::marker::PhantomData,
                })
            };
        }
        match key.alg {
            SigningAlg::Rs256 => under!(Rs256),
            SigningAlg::Rs384 => under!(Rs384),
            SigningAlg::Rs512 => under!(Rs512),
            SigningAlg::Ps256 => under!(Ps256),
            SigningAlg::Ps384 => under!(Ps384),
            SigningAlg::Ps512 => under!(Ps512),
            SigningAlg::Es256 => under!(Es256),
            SigningAlg::Es384 => under!(Es384),
            #[cfg(feature = "es512")]
            SigningAlg::Es512 => under!(crate::Es512),
            SigningAlg::EdDsa => under!(EdDsa),
            _ => Err(ErrorKind::UnsupportedAlg.into()),
        }
    }
}

impl Payload {
    /// The payload bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Jws<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Jws").field("kids", &self.kids).finish()
    }
}

impl fmt::Debug for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Payload")
            .field("len", &self.0.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::String;

    use base::b64url_encode;

    use super::Jws;
    use crate::{ErrorKind, MAX_COMPACT_LEN};

    fn token(header: &str) -> String {
        format!("{}.AA.AA", b64url_encode(header.as_bytes()))
    }

    fn kind(header: &str) -> Option<ErrorKind> {
        Jws::parse(&token(header)).err().map(|e| e.kind())
    }

    //= https://www.rfc-editor.org/rfc/rfc7515#section-4.1.4
    //= type=test
    //# Its value MUST be a case-sensitive string.
    #[test]
    fn crit_kinds() {
        assert_eq!(
            kind(r#"{"alg":"HS256","crit":["x"],"x":1}"#),
            Some(ErrorKind::CriticalHeader)
        );
        assert_eq!(
            kind(r#"{"alg":"HS256","crit":["x","y"],"x":1}"#),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            kind(r#"{"alg":"HS256","crit":[]}"#),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            kind(r#"{"alg":"HS256","crit":["alg"]}"#),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            kind(r#"{"alg":"HS256","crit":["x"]}"#),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            kind(r#"{"alg":"HS256","crit":"x","x":1}"#),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            kind(r#"{"alg":"HS256","b64":false}"#),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            kind(r#"{"alg":"HS256","kid":5}"#),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(kind(r#"{"alg":"HS256"}"#), None);
    }

    #[test]
    fn length_and_segments() {
        let long = |payload: usize| format!("eyJhbGciOiJIUzI1NiJ9.{}.AAAA", "A".repeat(payload));
        assert_eq!(long(MAX_COMPACT_LEN - 26).len(), MAX_COMPACT_LEN);
        assert_eq!(
            Jws::parse(&long(MAX_COMPACT_LEN - 26)).map(|j| j.kids().len()),
            Ok(0)
        );
        let over = long(MAX_COMPACT_LEN - 25);
        assert_eq!(
            Jws::parse(&over).err().map(|e| e.kind()),
            Some(ErrorKind::TooLarge)
        );
        let head = b64url_encode(br#"{"alg":"HS256"}"#);
        for text in [
            format!("{head}.AA"),
            format!("{head}.AA.AA.AA"),
            format!("{head}..AA="),
        ] {
            assert_eq!(
                Jws::parse(&text).err().map(|e| e.kind()),
                Some(ErrorKind::Malformed),
                "{text}"
            );
        }
        assert_eq!(
            Jws::parse(&format!("{head}..")).map(|j| j.kids().len()),
            Ok(0)
        );
    }

    #[test]
    fn kids_and_debug() {
        let text = token(r#"{"alg":"HS256","kid":"first"}"#);
        let jws = Jws::parse(&text).ok();
        assert_eq!(jws.as_ref().map(|j| j.kids().len()), Some(1));
        assert_eq!(
            jws.as_ref()
                .and_then(|j| j.kids().first())
                .map(|k| k.as_str()),
            Some("first")
        );
        let shown = format!("{jws:?}");
        assert!(shown.contains("first") && !shown.contains("AA"), "{shown}");
        assert_eq!(
            format!("{:?}", super::Payload(alloc::vec![1, 2, 3])),
            "Payload { len: 3 }"
        );
        assert_eq!(super::Payload(alloc::vec![7]).bytes(), [7]);
        let hinted = token(r#"{"alg":"HS256","kid":""}"#);
        assert_eq!(Jws::parse(&hinted).ok().map(|j| j.kids().len()), Some(0));
    }
}
