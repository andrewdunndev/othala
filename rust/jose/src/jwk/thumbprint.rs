//! JWK thumbprints (RFC 7638) and the `kid` made from one.
use alloc::format;
use alloc::string::String;

use base::{Digest, b64url_encode};
use p256::elliptic_curve::sec1::ToSec1Point as _;
use rsa::traits::PublicKeyParts as _;
use sha2::{Digest as _, Sha256};

use crate::jwk::decode::public_of;
use crate::key::Public;
use crate::{Jwk, Kid, SecretJwk};

/// The members a thumbprint covers, in lexicographic order, from the validated key: its encoding is canonical
/// (full-length coordinates, minimal integers), so it equals the text a JWK carried.
fn canonical(key: &Public) -> String {
    macro_rules! ec {
        ($crv:literal, $key:expr) => {{
            let point = $key.to_sec1_point(false);
            let coordinate =
                |c: Option<&_>| b64url_encode(c.map(AsRef::<[u8]>::as_ref).unwrap_or_default());
            format!(
                r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
                $crv,
                coordinate(point.x()),
                coordinate(point.y())
            )
        }};
    }
    match key {
        Public::Oct(k) => format!(r#"{{"k":"{}","kty":"oct"}}"#, b64url_encode(k.expose())),
        Public::P256(k) => ec!("P-256", k),
        Public::P384(k) => ec!("P-384", k),
        #[cfg(feature = "es512")]
        Public::P521(k) => ec!("P-521", k),
        Public::Ed25519(k) => format!(
            r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
            b64url_encode(k.as_bytes())
        ),
        Public::Rsa(k) => format!(
            r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
            b64url_encode(&k.e().to_be_bytes_trimmed_vartime()),
            b64url_encode(&k.n().as_ref().to_be_bytes_trimmed_vartime())
        ),
    }
}

fn thumbprint(key: &Public) -> Digest {
    Digest::from_bytes(Sha256::digest(canonical(key)).into())
}

impl Jwk {
    /// The RFC 7638 SHA-256 thumbprint, over the required members only.
    pub fn thumbprint(&self) -> Digest {
        thumbprint(&self.material)
    }
}

impl SecretJwk {
    /// The RFC 7638 SHA-256 thumbprint, over the required members only; a private key's is its public key's.
    pub fn thumbprint(&self) -> Digest {
        thumbprint(&public_of(&self.material))
    }
}

impl Kid {
    /// The `kid` for a thumbprint: its 43-character base64url text.
    pub fn from_thumbprint(thumbprint: &Digest) -> Self {
        Self(thumbprint.to_b64url())
    }
}
