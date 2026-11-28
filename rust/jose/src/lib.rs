//! JWS, JWE, JWK, JWA and JWT (RFC 7515 to 7519, 7638, 8037) with each algorithm bound to its key's type,
//! and the RFC 8725 practices as the only behaviour. No clock, no randomness of its own, no I/O.
//!
//! Features, all off by default: `es512` (ES512, and ECDH-ES on P-521); `rsa-sign` (RS and PS signing) and
//! `rsa-decrypt` (RSA-OAEP decryption). Both RSA features carry the Marvin residual risk: the `rsa` crate's
//! private-key operations are unaudited and their constant time rests on `crypto-bigint` (RUSTSEC-2023-0071), so
//! enable them only where an RSA private key is required, such as RS256 ID tokens.
#![no_std]
#![expect(
    dead_code,
    reason = "private representations are read by the bodies that later items land"
)]

extern crate alloc;

mod alg;
mod claims;
mod crit;
mod error;
mod json;
mod jwt;
mod key;
#[cfg(any(feature = "rsa-decrypt", feature = "rsa-sign"))]
mod rng;
mod sign;
#[cfg(test)]
mod testing;
mod jwk {
    pub(crate) mod decode;
    pub(crate) mod set;
    pub(crate) mod thumbprint;
}
mod jws {
    pub(crate) mod compact;
    pub(crate) mod header;
    pub(crate) mod json;
}
mod sig {
    pub(crate) mod ecdsa;
    #[cfg(feature = "es512")]
    pub(crate) mod ecdsa_p521;
    pub(crate) mod eddsa;
    pub(crate) mod hmac;
    pub(crate) mod pss;
    pub(crate) mod rsa;
    #[cfg(feature = "rsa-sign")]
    pub(crate) mod rsa_sign;
}
mod jwe {
    pub(crate) mod content;
    pub(crate) mod ecdh;
    pub(crate) mod envelope;
    pub(crate) mod kw;
    #[cfg(feature = "rsa-decrypt")]
    pub(crate) mod oaep;
}

#[cfg(feature = "rsa-sign")]
pub use alg::BlindedAlg;
#[cfg(feature = "rsa-decrypt")]
pub use alg::BlindedKeyAlg;
pub use alg::{
    Alg, Enc, JweAlg, JweEnc, KeyAlg, LocalAlg, LocalKeyAlg, PublicAlg, PublicKeyAlg, SignAlg,
    SigningAlg,
};
pub use claims::{Audience, Expiry, Issuer, Leeway, Policy, ReadBack, TokenKind, Typ};
pub use error::{Error, ErrorKind};
pub use jwe::content::{A128CbcHs256, A128Gcm, A192CbcHs384, A192Gcm, A256CbcHs512, A256Gcm};
pub use jwe::ecdh::{EcdhEs, EcdhEsA128Kw, EcdhEsA192Kw, EcdhEsA256Kw};
pub use jwe::envelope::{DecryptKey, EncryptKey, Jwe, Plaintext};
pub use jwe::kw::{A128GcmKw, A128Kw, A192GcmKw, A192Kw, A256GcmKw, A256Kw, Dir};
#[cfg(feature = "rsa-decrypt")]
pub use jwe::oaep::{RsaOaep, RsaOaep256};
pub use jwk::decode::{Jwk, Kid, Kty, SecretJwk};
pub use jwk::set::{JwkEntry, JwkSet};
pub use jws::compact::{Jws, Payload};
pub use jwt::{Jwt, VerifiedJwt};
pub use key::any::{AnySigningKey, AnyVerifyKey};
pub use key::{Signer, VerifyKey};
pub use sig::ecdsa::{Es256, Es384};
#[cfg(feature = "es512")]
pub use sig::ecdsa_p521::Es512;
pub use sig::eddsa::EdDsa;
pub use sig::hmac::{Hs256, Hs384, Hs512};
pub use sig::pss::{Ps256, Ps384, Ps512};
pub use sig::rsa::{Rs256, Rs384, Rs512};
pub use sign::{Compact, Header, SigningKey, Unsigned};

/// Bytes of compact JWS, JWT or JWE text a parser reads or an issuer writes; longer is `TooLarge`.
pub const MAX_COMPACT_LEN: usize = 16_384;
/// Bytes of a JSON serialization, JWK or JWK Set document a parser reads; longer is `TooLarge`.
pub const MAX_JSON_LEN: usize = 65_536;
/// Nesting depth of any JSON value a parser reads (headers, claims, JWKs); deeper is `TooLarge`.
pub const MAX_JSON_DEPTH: usize = 32;
/// Keys a JWK Set keeps; more is `TooLarge`.
pub const MAX_JWKS_KEYS: usize = 32;
/// Signatures in one general JWS, and recipients in one general JWE; more is `TooLarge`.
pub const MAX_ENTRIES: usize = 8;
/// Bytes of one `kid`, issuer or audience; longer is `TooLarge`.
pub const MAX_NAME_LEN: usize = 256;
/// Seconds of clock leeway a [`Leeway`] admits; more is `TooLarge`.
pub const MAX_LEEWAY: u64 = 300;
/// Smallest RSA modulus in bits; smaller is `WeakKey`.
pub const MIN_RSA_BITS: usize = 2048;
/// Largest RSA modulus in bits; larger is `TooLarge`.
pub const MAX_RSA_BITS: usize = 8192;
/// Largest RSA public exponent; larger is `TooLarge`.
pub const MAX_RSA_EXPONENT: u64 = (1 << 33) - 1;
