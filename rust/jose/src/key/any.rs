use core::fmt;

use crate::alg::sealed;
use crate::jwk::decode::{Meta, SIGN, VERIFY};
use crate::key::{Private, Public};
use crate::key::{dup, dup_private, private_info, public_info};
use crate::{Error, ErrorKind, Jwk, LocalAlg, SecretJwk, Signer, SigningAlg};

/// A verification key bound at runtime to one algorithm, for JWK Set consumers. Not `Clone`, `Debug` redacted.
pub struct AnyVerifyKey {
    pub(crate) alg: SigningAlg,
    pub(crate) material: Public,
}

/// A signing key bound at runtime to its JWK's `alg`, for a host that signs by `kid`: HS, ES and EdDSA.
/// Not `Clone`, not `Serialize`, `Debug` redacted.
pub struct AnySigningKey {
    pub(crate) alg: SigningAlg,
    pub(crate) material: Private,
}

/// The algorithm a JWK names for itself: its `alg` is required (`KeyAlgMissing`), `op` must be permitted (`KeyUse`, so
/// an `enc`-only key is refused) and the value must be a JWS algorithm.
fn named(meta: &Meta, op: u8) -> Result<SigningAlg, Error> {
    if meta.alg.is_none() {
        return Err(ErrorKind::KeyAlgMissing.into());
    }
    if meta.usage.0 & op == 0 {
        return Err(ErrorKind::KeyUse.into());
    }
    meta.sig_alg().ok_or_else(|| ErrorKind::AlgMismatch.into())
}

impl AnyVerifyKey {
    /// Binds the JWK's own `alg`, which must exist and which its key type must take.
    pub fn from_jwk(jwk: &Jwk) -> Result<Self, Error> {
        let alg = named(&jwk.meta, VERIFY)?;
        Self::from_jwk_for(jwk, alg)
    }

    /// Binds the algorithm the host expects; a JWK `alg` that differs is `AlgMismatch`.
    pub fn from_jwk_for(jwk: &Jwk, alg: SigningAlg) -> Result<Self, Error> {
        jwk.meta
            .check_sig(public_info(&jwk.material), alg, VERIFY)?;
        Ok(Self {
            alg,
            material: dup(&jwk.material),
        })
    }

    /// The algorithm this key verifies.
    pub const fn alg(&self) -> SigningAlg {
        self.alg
    }
}

impl AnySigningKey {
    /// Binds the JWK's own `alg`; RS and PS sign only through `sign_blinded`, so they are `UnsupportedAlg`.
    pub fn from_jwk(jwk: &SecretJwk) -> Result<Self, Error> {
        let alg = named(&jwk.meta, SIGN)?;
        if sig_blinded(alg) {
            return Err(ErrorKind::UnsupportedAlg.into());
        }
        jwk.meta.check_sig(private_info(&jwk.material), alg, SIGN)?;
        Ok(Self {
            alg,
            material: dup_private(&jwk.material),
        })
    }

    /// The algorithm this key signs.
    pub const fn alg(&self) -> SigningAlg {
        self.alg
    }
}

const fn sig_blinded(alg: SigningAlg) -> bool {
    matches!(
        alg,
        SigningAlg::Rs256
            | SigningAlg::Rs384
            | SigningAlg::Rs512
            | SigningAlg::Ps256
            | SigningAlg::Ps384
            | SigningAlg::Ps512
    )
}

impl<A: LocalAlg> Signer<A> for AnySigningKey {
    fn sign(&self, input: &[u8]) -> Result<A::Signature, Error> {
        if A::ALG != self.alg {
            return Err(ErrorKind::AlgMismatch.into());
        }
        <A as sealed::Local>::sign(&self.material, input)
    }
}

impl fmt::Debug for AnyVerifyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnyVerifyKey")
            .field("alg", &self.alg)
            .finish()
    }
}

impl fmt::Debug for AnySigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnySigningKey")
            .field("alg", &self.alg)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::{AnySigningKey, AnyVerifyKey};
    use crate::{EdDsa, ErrorKind, Es256, Hs256, Hs384, Jwk, SecretJwk, Signer, SigningAlg};

    const OCT: &str =
        r#"{"kty":"oct","alg":"HS256","k":"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"}"#;

    #[test]
    fn sign_binds() {
        let key = SecretJwk::decode(OCT.as_bytes()).and_then(|k| AnySigningKey::from_jwk(&k));
        let key = key.ok();
        assert_eq!(
            key.as_ref().map(AnySigningKey::alg),
            Some(SigningAlg::Hs256)
        );
        let signed = key
            .as_ref()
            .map(|k| Signer::<Hs256>::sign(k, b"input").map(|s| s.len()));
        assert_eq!(signed.and_then(Result::ok), Some(32));
        let other = key
            .as_ref()
            .map(|k| Signer::<Hs384>::sign(k, b"input").err().map(|e| e.kind()));
        assert_eq!(other, Some(Some(ErrorKind::AlgMismatch)));
        let other = key
            .as_ref()
            .map(|k| Signer::<Hs256>::sign(k, b"").map(|s| s[..4] == [0; 4]));
        assert_eq!(other.and_then(Result::ok), Some(false));
        assert_eq!(format!("{key:?}"), "Some(AnySigningKey { alg: Hs256 })");
    }

    #[test]
    fn jwk_alg_rules() {
        let secret = |member: &str| {
            let text = OCT.replace(r#""alg":"HS256","#, member);
            SecretJwk::decode(text.as_bytes()).and_then(|k| AnySigningKey::from_jwk(&k))
        };
        let kind = |r: Result<AnySigningKey, crate::Error>| r.err().map(|e| e.kind());
        assert_eq!(kind(secret("")), Some(ErrorKind::KeyAlgMissing));
        assert_eq!(
            kind(secret(r#""alg":"A128KW","#)),
            Some(ErrorKind::AlgMismatch)
        );
        assert_eq!(
            kind(secret(r#""alg":"RS256","#)),
            Some(ErrorKind::UnsupportedAlg)
        );
        assert_eq!(
            kind(secret(r#""alg":"ES256","#)),
            Some(ErrorKind::AlgMismatch)
        );
        assert_eq!(
            kind(secret(r#""alg":"HS256","use":"enc","#)),
            Some(ErrorKind::KeyUse)
        );
        assert_eq!(
            kind(secret(r#""alg":"HS256","key_ops":["verify"],"#)),
            Some(ErrorKind::KeyUse)
        );
        assert_eq!(kind(secret(r#""alg":"HS256","#)), None);
        let _ = (Es256, EdDsa);
    }

    const EC: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"#;

    #[test]
    fn verify_key_binding() {
        let key = |tail: &str| Jwk::decode(format!(r#"{EC}"{tail}}}"#).as_bytes());
        let from = |tail: &str| key(tail).and_then(|k| AnyVerifyKey::from_jwk(&k));
        let kind = |r: Result<AnyVerifyKey, crate::Error>| r.err().map(|e| e.kind());
        assert_eq!(kind(from("")), Some(ErrorKind::KeyAlgMissing));
        assert_eq!(kind(from(r#","alg":"ES256""#)), None);
        assert_eq!(
            kind(from(r#","alg":"ES384""#)),
            Some(ErrorKind::AlgMismatch)
        );
        assert_eq!(
            kind(from(r#","alg":"ECDH-ES""#)),
            Some(ErrorKind::AlgMismatch)
        );
        assert_eq!(
            kind(from(r#","alg":"ES256","use":"enc""#)),
            Some(ErrorKind::KeyUse)
        );
        let bound = |tail: &str, alg| key(tail).and_then(|k| AnyVerifyKey::from_jwk_for(&k, alg));
        assert_eq!(
            bound("", SigningAlg::Es256).ok().map(|k| k.alg()),
            Some(SigningAlg::Es256)
        );
        assert_eq!(
            bound(r#","alg":"ES256""#, SigningAlg::Es384)
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::AlgMismatch)
        );
        assert_eq!(
            bound("", SigningAlg::Hs256).err().map(|e| e.kind()),
            Some(ErrorKind::AlgMismatch)
        );
        let shown = from(r#","alg":"ES256""#).ok();
        assert_eq!(format!("{shown:?}"), "Some(AnyVerifyKey { alg: Es256 })");
    }
}
