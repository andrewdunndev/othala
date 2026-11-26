use crate::{Error, key};

/// Per-family operations, implemented beside each family's markers; sealing [`Alg`] keeps the set reviewed.
#[expect(
    private_interfaces,
    reason = "sealed: these traits are unnameable outside the crate"
)]
pub(crate) mod sealed {
    use super::{Error, key};

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
pub trait KeyAlg: crate::jwe::envelope::sealed::KeyAlg {
    /// Its registry value.
    const ALG: JweAlg;
}

/// A key-management algorithm whose encryption key is public: ECDH-ES and RSA-OAEP.
pub trait PublicKeyAlg: KeyAlg {}

/// A key-management algorithm whose decryption needs no randomness: every one but RSA-OAEP.
pub trait LocalKeyAlg: KeyAlg + crate::jwe::envelope::sealed::Unwrap {}

/// A key-management algorithm whose private-key operation is blinded from the caller's entropy: RSA-OAEP
/// (feature `rsa-decrypt`, which carries the Marvin residual risk), decrypted through `Jwe::decrypt_blinded`.
#[cfg(feature = "rsa-decrypt")]
pub trait BlindedKeyAlg: KeyAlg + crate::jwe::envelope::sealed::BlindedUnwrap {}

/// A JWE content-encryption algorithm (RFC 7518 section 5): one marker type each, sealed.
pub trait Enc: crate::jwe::envelope::sealed::Enc {
    /// Its registry value.
    const ENC: JweEnc;
}

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
