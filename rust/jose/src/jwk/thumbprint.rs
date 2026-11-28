//! JWK thumbprints (RFC 7638) and the `kid` made from one.
use alloc::borrow::ToOwned as _;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use base::{Digest, b64url_encode};
use expose::Expose as _;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use rsa::traits::PublicKeyParts as _;
use sha2::{Digest as _, Sha256};

use crate::key::Public;
use crate::key::public_of;
use crate::{Jwk, Kid, SecretJwk};

//= https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7
//= type=exception
//= reason=jose writes no private JWK (SecretJwk is not Serialize, T16), so it produces no oth member; a decoder refuses any key that carries oth
//# Each array element MUST be an object with the following members.
//= https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7
//= type=exception
//= reason=jose writes no private JWK (SecretJwk is not Serialize, T16), so it produces no oth member; a decoder refuses any key that carries oth
//# When three or more primes have been used, the number of array elements MUST be the number of
//# primes used minus two.
//= https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2.7
//= type=exception
//= reason=jose writes no private JWK (SecretJwk is not Serialize, T16), so it produces no oth member; a decoder refuses any key that carries oth
//# When only two primes have been used (the normal case), this parameter MUST be omitted.
//= https://www.rfc-editor.org/rfc/rfc7518#section-6.3.2
//= type=exception
//= reason=jose writes no private JWK (SecretJwk is not Serialize, T16), so it produces no oth member; a decoder refuses any key that carries oth
//# If the producer includes any of the other private key parameters, then all of the others MUST be
//# present, with the exception of "oth", which MUST only be present when more than two prime
//# factors were used.
/// A key's JWK members besides `kid`, `alg`, `use` and `key_ops`, `kty` first: canonical (full-length coordinates,
/// minimal integers), so they equal the text a JWK carried.
pub(crate) fn members(key: &Public) -> Vec<(&'static str, String)> {
    macro_rules! ec {
        ($crv:literal, $key:expr) => {{
            let point = $key.to_sec1_point(false);
            let coordinate =
                |c: Option<&_>| b64url_encode(c.map(AsRef::<[u8]>::as_ref).unwrap_or_default());
            vec![
                ("kty", "EC".to_owned()),
                ("crv", $crv.to_owned()),
                ("x", coordinate(point.x())),
                ("y", coordinate(point.y())),
            ]
        }};
    }
    match key {
        Public::Oct(k) => vec![("kty", "oct".to_owned()), ("k", b64url_encode(k.expose()))],
        Public::P256(k) => ec!("P-256", k),
        Public::P384(k) => ec!("P-384", k),
        #[cfg(feature = "es512")]
        Public::P521(k) => ec!("P-521", k),
        Public::Ed25519(k) => vec![
            ("kty", "OKP".to_owned()),
            ("crv", "Ed25519".to_owned()),
            ("x", b64url_encode(k.as_bytes())),
        ],
        Public::Rsa(k) => vec![
            ("kty", "RSA".to_owned()),
            (
                "n",
                b64url_encode(&k.n().as_ref().to_be_bytes_trimmed_vartime()),
            ),
            ("e", b64url_encode(&k.e().to_be_bytes_trimmed_vartime())),
        ],
    }
}

/// The members a thumbprint covers, in lexicographic order and without whitespace.
fn canonical(key: &Public) -> String {
    let sorted: BTreeMap<&str, String> = members(key).into_iter().collect();
    serde_json::to_string(&sorted).unwrap_or_default()
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
