use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::key::Public;
use crate::{Error, ErrorKind, key};

/// Per-algorithm operations, implemented beside each family's markers; sealing the marker traits keeps the set reviewed.
#[expect(
    private_interfaces,
    reason = "sealed: these traits are unnameable outside the crate"
)]
pub(crate) mod sealed {
    use alloc::vec::Vec;

    use base::{Entropy, SecretBytes};

    use super::{Error, JweEnc, Params, key};
    use crate::key::{Private, Public};

    /// Verifies one family's signatures.
    pub trait Alg {
        /// `Ok` when `signature` is this algorithm's over `input` under `key`; a key of another family is `AlgMismatch`.
        fn verify(key: &key::Public, input: &[u8], signature: &[u8]) -> Result<(), Error>;
    }

    /// Signs without randomness: HS, ES and EdDSA.
    pub trait Local: crate::Alg {
        /// The signature over `input`; a key of another family is `AlgMismatch`.
        fn sign(key: &key::Private, input: &[u8]) -> Result<Self::Signature, Error>;
    }

    /// Signs through a blinded private-key operation: RS and PS.
    #[cfg(feature = "rsa-sign")]
    pub trait Blinded: crate::Alg {
        /// The signature over `input`, blinding and any salt drawn from `e`.
        fn sign(
            key: &key::Private,
            input: &[u8],
            e: &mut dyn base::Entropy,
        ) -> Result<Self::Signature, Error>;
    }

    /// Makes one recipient's content-encryption key.
    pub trait KeyAlg {
        /// The CEK for `enc` and the JWE Encrypted Key (empty for direct use and agreement); any header parameter the
        /// algorithm adds (`epk`, `iv`, `tag`) goes in `params`, and all randomness comes from `e`.
        fn wrap(
            key: &Public,
            enc: JweEnc,
            params: &mut Params,
            e: &mut dyn Entropy,
        ) -> Result<(SecretBytes, Vec<u8>), Error>;
    }

    /// Recovers one recipient's content-encryption key without randomness.
    pub trait Unwrap: KeyAlg {
        /// The CEK for `enc`; any failure is `Decrypt`.
        fn unwrap(
            key: &Private,
            encrypted_key: &[u8],
            enc: JweEnc,
            params: &Params,
        ) -> Result<SecretBytes, Error>;
    }

    /// Recovers one recipient's content-encryption key through a blinded private-key operation, on one path: an
    /// OAEP failure yields a random CEK of the same length, so the content step fails as `Decrypt` (RFC 7516 11.5).
    #[cfg(feature = "rsa-decrypt")]
    pub trait BlindedUnwrap: KeyAlg {
        /// The CEK for `enc`, or a random one drawn from `e`.
        fn unwrap(
            key: &Private,
            encrypted_key: &[u8],
            enc: JweEnc,
            e: &mut dyn Entropy,
        ) -> SecretBytes;
    }

    /// Encrypts and decrypts content under a CEK.
    pub trait Enc {
        /// The CEK length in bytes.
        const CEK_LEN: usize;
        /// The IV length in bytes.
        const IV_LEN: usize;
        /// The ciphertext and authentication tag of `plaintext` under `cek`, `iv` and `aad`.
        fn seal(
            cek: &SecretBytes,
            iv: &[u8],
            aad: &[u8],
            plaintext: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>), Error>;
        /// The plaintext; any failure is `Decrypt`.
        fn open(
            cek: &SecretBytes,
            iv: &[u8],
            aad: &[u8],
            ciphertext: &[u8],
            tag: &[u8],
        ) -> Result<SecretBytes, Error>;
    }
}

/// One recipient's key-management header parameters.
pub(crate) struct Params {
    pub(crate) epk: Option<Arc<Public>>,
    pub(crate) apu: Vec<u8>,
    pub(crate) apv: Vec<u8>,
    pub(crate) iv: Option<[u8; 12]>,
    pub(crate) tag: Option<[u8; 16]>,
}

/// A JWS algorithm (RFC 7518 section 3, RFC 8037 section 3.1): one marker type each, sealed.
pub trait Alg: sealed::Alg {
    /// Its registry value.
    const ALG: SigningAlg;
    /// A signature in the RFC 7518 encoding: a fixed-size array for HS, ES and EdDSA (ECDSA as `R || S`),
    /// the modulus-length octets for RS and PS.
    type Signature: AsRef<[u8]> + for<'a> TryFrom<&'a [u8]>;
}

/// A JWS algorithm whose verification key is public, so a [`crate::Jwk`] can carry it: RS, PS, ES and EdDSA, never HS.
pub trait PublicAlg: Alg {}

/// A JWS algorithm this crate's own keys sign: HS, ES and EdDSA, and RS and PS under the `rsa-sign` feature.
pub trait SignAlg: Alg {}

/// A JWS algorithm whose signature needs no randomness, so a [`crate::SigningKey`] is its [`crate::Signer`]:
/// HS, ES and EdDSA.
pub trait LocalAlg: SignAlg + sealed::Local {}

/// A JWS algorithm whose private-key operation is blinded and salted from the caller's entropy: RS and PS
/// (feature `rsa-sign`, which carries the Marvin residual risk), signed through `Unsigned::sign_blinded`.
#[cfg(feature = "rsa-sign")]
pub trait BlindedAlg: SignAlg + sealed::Blinded {}

/// A JWE key-management algorithm (RFC 7518 section 4): one marker type each, sealed.
pub trait KeyAlg: sealed::KeyAlg {
    /// Its registry value.
    const ALG: JweAlg;
}

/// A key-management algorithm whose encryption key is public: ECDH-ES and RSA-OAEP.
pub trait PublicKeyAlg: KeyAlg {}

/// A key-management algorithm whose decryption needs no randomness: every one but RSA-OAEP.
pub trait LocalKeyAlg: KeyAlg + sealed::Unwrap {}

/// A key-management algorithm whose private-key operation is blinded from the caller's entropy: RSA-OAEP
/// (feature `rsa-decrypt`, which carries the Marvin residual risk), decrypted through `Jwe::decrypt_blinded`.
#[cfg(feature = "rsa-decrypt")]
pub trait BlindedKeyAlg: KeyAlg + sealed::BlindedUnwrap {}

/// A JWE content-encryption algorithm (RFC 7518 section 5): one marker type each, sealed.
pub trait Enc: sealed::Enc {
    /// Its registry value.
    const ENC: JweEnc;
}

//= https://www.rfc-editor.org/rfc/rfc7518#section-3.6
//= type=exception
//= reason=alg none is not shipped: no SigningAlg variant, so no unsecured JWS is made or accepted; non-goal N1 (R2, R4, T12)
//# In order to mitigate downgrade attacks, applications MUST NOT signal acceptance of Unsecured
//# JWSs at a global level, and SHOULD signal acceptance on a per-object basis.
//= https://www.rfc-editor.org/rfc/rfc7518#section-3.6
//= type=exception
//= reason=alg none is not shipped: no SigningAlg variant, so no unsecured JWS is made or accepted; non-goal N1 (R2, R4, T12)
//# Implementations MUST NOT accept Unsecured JWSs by default.
//= https://www.rfc-editor.org/rfc/rfc7518#section-3.6
//= type=exception
//= reason=alg none is not shipped: no SigningAlg variant, so no unsecured JWS is made or accepted; non-goal N1 (R2, R4, T12)
//# Implementations that support Unsecured JWSs MUST NOT accept such objects as valid unless the
//# application specifies that it is acceptable for a specific object to not be integrity protected.
//= https://www.rfc-editor.org/rfc/rfc7518#section-3.6
//= type=exception
//= reason=alg none is not shipped: no SigningAlg variant, so no unsecured JWS is made or accepted; non-goal N1 (R2, R4, T12)
//# Recipients MUST verify that the JWS Signature value is the empty octet sequence.
//= https://www.rfc-editor.org/rfc/rfc7518#section-3.6
//= type=exception
//= reason=alg none is not shipped: no SigningAlg variant, so no unsecured JWS is made or accepted; non-goal N1 (R2, R4, T12)
//# An Unsecured JWS uses the "alg" value "none" and is formatted identically to other JWSs, but
//# MUST use the empty octet sequence as its JWS Signature value.
//= https://www.rfc-editor.org/rfc/rfc7519#section-8
//= type=exception
//= reason=HS256 is implemented; none is non-goal N1 (RFC 8725 3.2)
//# Of the signature and MAC algorithms specified in JSON Web Algorithms [JWA], only HMAC SHA-256
//# ("HS256") and "none" MUST be implemented by conforming JWT implementations.
/// A JWS `alg` value this crate implements (RFC 7518 section 3.1, RFC 8037 section 3.1); `none` has no variant.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SigningAlg {
    /// `HS256`.
    Hs256,
    /// `HS384`.
    Hs384,
    /// `HS512`.
    Hs512,
    /// `RS256`.
    Rs256,
    /// `RS384`.
    Rs384,
    /// `RS512`.
    Rs512,
    /// `PS256`.
    Ps256,
    /// `PS384`.
    Ps384,
    /// `PS512`.
    Ps512,
    /// `ES256`.
    Es256,
    /// `ES384`.
    Es384,
    /// `ES512`; with the `es512` feature off, a key or token for it is `UnsupportedAlg`.
    Es512,
    /// `EdDSA`, Ed25519 only.
    EdDsa,
}

//= https://www.rfc-editor.org/rfc/rfc7518#section-4.8.1.2
//= type=exception
//= reason=PBES2 is not shipped: no JweAlg variant, since an attacker-chosen p2c is a denial of service; non-goal N3
//# This Header Parameter MUST be present and MUST be understood and processed by implementations
//# when these algorithms are used.
//= https://www.rfc-editor.org/rfc/rfc7518#section-4.8.1.1
//= type=exception
//= reason=PBES2 is not shipped: no JweAlg variant, since an attacker-chosen p2c is a denial of service; non-goal N3
//# A new Salt Input value MUST be generated randomly for every encryption operation; see RFC 4086
//# [RFC4086] for considerations on generating random values.
//= https://www.rfc-editor.org/rfc/rfc7518#section-4.8.1.1
//= type=exception
//= reason=PBES2 is not shipped: no JweAlg variant, since an attacker-chosen p2c is a denial of service; non-goal N3
//# A Salt Input value containing 8 or more octets MUST be used.
//= https://www.rfc-editor.org/rfc/rfc7518#section-4.8.1.1
//= type=exception
//= reason=PBES2 is not shipped: no JweAlg variant, since an attacker-chosen p2c is a denial of service; non-goal N3
//# This Header Parameter MUST be present and MUST be understood and processed by implementations
//# when these algorithms are used.
//= https://www.rfc-editor.org/rfc/rfc7518#section-4.8
//= type=exception
//= reason=PBES2 is not shipped: no JweAlg variant, since an attacker-chosen p2c is a denial of service; non-goal N3
//# The iteration count parameter MUST be provided as the "p2c" (PBES2 count) Header Parameter
//# value.
//= https://www.rfc-editor.org/rfc/rfc7518#section-4.8
//= type=exception
//= reason=PBES2 is not shipped: no JweAlg variant, since an attacker-chosen p2c is a denial of service; non-goal N3
//# The salt parameter MUST be computed from the "p2s" (PBES2 salt input) Header Parameter value and
//# the "alg" (algorithm) Header Parameter value as specified in the "p2s" definition below.
//= https://www.rfc-editor.org/rfc/rfc7518#section-4.8
//= type=exception
//= reason=PBES2 is not shipped: no JweAlg variant, since an attacker-chosen p2c is a denial of service; non-goal N3
//# The PBES2 password input is an octet sequence; if the password to be used is represented as a
//# text string rather than an octet sequence, the UTF-8 encoding of the text string MUST be used as
//# the octet sequence.
//= https://www.rfc-editor.org/rfc/rfc7518#section-4.2
//= type=exception
//= reason=RSA1_5 is not shipped: no JweAlg variant; non-goal N2
//# A key of size 2048 bits or larger MUST be used with this algorithm.
//= https://www.rfc-editor.org/rfc/rfc7519#section-8
//= type=exception
//= reason=A128KW, A256KW, A128CBC-HS256, A256CBC-HS512 are implemented; RSA1_5 is non-goal N2
//# If an implementation provides encryption capabilities, of the encryption algorithms specified in
//# [JWA], only RSAES-PKCS1-v1_5 with 2048-bit keys ("RSA1_5"), AES Key Wrap with 128- and 256-bit
//# keys ("A128KW" and "A256KW"), and the composite authenticated encryption algorithm using AES-CBC
//# and HMAC SHA-2 ("A128CBC-HS256" and "A256CBC-HS512") MUST be implemented by conforming
//# implementations.
/// A JWE `alg` value this crate implements (RFC 7518 section 4.1); `RSA1_5` and `PBES2-*` have no variant.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JweAlg {
    /// `A128KW`.
    A128Kw,
    /// `A192KW`.
    A192Kw,
    /// `A256KW`.
    A256Kw,
    /// `A128GCMKW`.
    A128GcmKw,
    /// `A192GCMKW`.
    A192GcmKw,
    /// `A256GCMKW`.
    A256GcmKw,
    /// `dir`.
    Dir,
    /// `ECDH-ES`.
    EcdhEs,
    /// `ECDH-ES+A128KW`.
    EcdhEsA128Kw,
    /// `ECDH-ES+A192KW`.
    EcdhEsA192Kw,
    /// `ECDH-ES+A256KW`.
    EcdhEsA256Kw,
    /// `RSA-OAEP`; with the `rsa-decrypt` feature off, a key or token for it is `UnsupportedAlg`.
    RsaOaep,
    /// `RSA-OAEP-256`; with the `rsa-decrypt` feature off, a key or token for it is `UnsupportedAlg`.
    RsaOaep256,
}

//= https://www.rfc-editor.org/rfc/rfc7516#section-4.1.2
//# This algorithm MUST be an AEAD algorithm with a specified key length.
/// A JWE `enc` value this crate implements (RFC 7518 section 5.1).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum JweEnc {
    /// `A128GCM`.
    A128Gcm,
    /// `A192GCM`.
    A192Gcm,
    /// `A256GCM`.
    A256Gcm,
    /// `A128CBC-HS256`.
    A128CbcHs256,
    /// `A192CBC-HS384`.
    A192CbcHs384,
    /// `A256CBC-HS512`.
    A256CbcHs512,
}

impl SigningAlg {
    /// The registry value.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hs256 => "HS256",
            Self::Hs384 => "HS384",
            Self::Hs512 => "HS512",
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
            Self::Es256 => "ES256",
            Self::Es384 => "ES384",
            Self::Es512 => "ES512",
            Self::EdDsa => "EdDSA",
        }
    }
}

impl JweAlg {
    /// The registry value.
    pub const fn name(self) -> &'static str {
        match self {
            Self::A128Kw => "A128KW",
            Self::A192Kw => "A192KW",
            Self::A256Kw => "A256KW",
            Self::A128GcmKw => "A128GCMKW",
            Self::A192GcmKw => "A192GCMKW",
            Self::A256GcmKw => "A256GCMKW",
            Self::Dir => "dir",
            Self::EcdhEs => "ECDH-ES",
            Self::EcdhEsA128Kw => "ECDH-ES+A128KW",
            Self::EcdhEsA192Kw => "ECDH-ES+A192KW",
            Self::EcdhEsA256Kw => "ECDH-ES+A256KW",
            Self::RsaOaep => "RSA-OAEP",
            Self::RsaOaep256 => "RSA-OAEP-256",
        }
    }
}

impl JweEnc {
    /// The registry value.
    pub const fn name(self) -> &'static str {
        match self {
            Self::A128Gcm => "A128GCM",
            Self::A192Gcm => "A192GCM",
            Self::A256Gcm => "A256GCM",
            Self::A128CbcHs256 => "A128CBC-HS256",
            Self::A192CbcHs384 => "A192CBC-HS384",
            Self::A256CbcHs512 => "A256CBC-HS512",
        }
    }
}

pub(crate) const SIGNING: [SigningAlg; 13] = [
    SigningAlg::Hs256,
    SigningAlg::Hs384,
    SigningAlg::Hs512,
    SigningAlg::Rs256,
    SigningAlg::Rs384,
    SigningAlg::Rs512,
    SigningAlg::Ps256,
    SigningAlg::Ps384,
    SigningAlg::Ps512,
    SigningAlg::Es256,
    SigningAlg::Es384,
    SigningAlg::Es512,
    SigningAlg::EdDsa,
];

pub(crate) const KEY_MANAGEMENT: [JweAlg; 13] = [
    JweAlg::A128Kw,
    JweAlg::A192Kw,
    JweAlg::A256Kw,
    JweAlg::A128GcmKw,
    JweAlg::A192GcmKw,
    JweAlg::A256GcmKw,
    JweAlg::Dir,
    JweAlg::EcdhEs,
    JweAlg::EcdhEsA128Kw,
    JweAlg::EcdhEsA192Kw,
    JweAlg::EcdhEsA256Kw,
    JweAlg::RsaOaep,
    JweAlg::RsaOaep256,
];

pub(crate) const CONTENT: [JweEnc; 6] = [
    JweEnc::A128Gcm,
    JweEnc::A192Gcm,
    JweEnc::A256Gcm,
    JweEnc::A128CbcHs256,
    JweEnc::A192CbcHs384,
    JweEnc::A256CbcHs512,
];

/// Every registry value a JWK's `alg` may carry: JWS `alg`, JWE `alg` and `enc`.
pub(crate) fn registry_names() -> impl Iterator<Item = &'static str> {
    let sig = SIGNING.into_iter().map(SigningAlg::name);
    let key = KEY_MANAGEMENT.into_iter().map(JweAlg::name);
    sig.chain(key).chain(CONTENT.into_iter().map(JweEnc::name))
}

/// The registry value spelled `name`, as a `'static` string.
pub(crate) fn registry_name(name: &str) -> Option<&'static str> {
    registry_names().find(|known| *known == name)
}

macro_rules! registry {
    ($type:ident, $all:expr) => {
        impl $type {
            /// The value for exactly this registry name, case-sensitively; any other is `UnsupportedAlg`.
            pub fn parse(name: &str) -> Result<Self, Error> {
                $all.into_iter()
                    .find(|alg| alg.name() == name)
                    .ok_or_else(|| ErrorKind::UnsupportedAlg.into())
            }
        }

        impl serde::Serialize for $type {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.name())
            }
        }

        impl<'de> serde::Deserialize<'de> for $type {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                // an owned string, so an escaped name or a deserializer that cannot lend still reads
                let name = <alloc::string::String>::deserialize(deserializer)?;
                Self::parse(&name).map_err(serde::de::Error::custom)
            }
        }
    };
}

registry!(SigningAlg, SIGNING);
registry!(JweAlg, KEY_MANAGEMENT);
registry!(JweEnc, CONTENT);

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned as _;

    use serde::Deserialize as _;
    use serde::de::value::StringDeserializer;

    use crate::SigningAlg;

    #[test]
    fn registry_names_read_escaped_and_from_owned_values() {
        assert_eq!(
            serde_json::from_str::<SigningAlg>(r#""ES256""#).ok(),
            Some(SigningAlg::Es256)
        );
        assert_eq!(
            SigningAlg::deserialize(StringDeserializer::<serde_json::Error>::new(
                "HS256".to_owned()
            ))
            .ok(),
            Some(SigningAlg::Hs256)
        );
        assert_eq!(
            serde_json::from_str::<SigningAlg>(r#""none""#)
                .err()
                .map(|e| alloc::format!("{e}")),
            Some("algorithm, curve or compression is not supported; choose an implemented one or enable its feature".into())
        );
    }
}
