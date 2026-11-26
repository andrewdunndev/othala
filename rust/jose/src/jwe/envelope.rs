//! JWE parsing, the recipient loop and issuing (RFC 7516), compact and JSON.
use alloc::vec::Vec;
use core::marker::PhantomData;

use base::SecretBytes;

use crate::key::{Private, Public};
use crate::{KeyAlg, Kid};

/// Per-algorithm operations, implemented beside each algorithm's markers.
#[expect(
    private_interfaces,
    reason = "sealed: these traits are unnameable outside the crate"
)]
pub(crate) mod sealed {
    use alloc::vec::Vec;

    use base::{Entropy, SecretBytes};

    use super::Params;
    use crate::key::{Private, Public};
    use crate::{Error, JweEnc};

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
    pub(crate) epk: Option<Public>,
    pub(crate) apu: Vec<u8>,
    pub(crate) apv: Vec<u8>,
    pub(crate) iv: Option<[u8; 12]>,
    pub(crate) tag: Option<[u8; 16]>,
}

/// A parsed JWE (RFC 7516), not decrypted: no accessor reaches its content, and `Debug` prints only the `kid`s.
pub struct Jwe<'a> {
    pub(crate) input: &'a [u8],
    pub(crate) kids: Vec<Kid>,
}

/// Decrypted JWE content and its authenticated `aad`. Not `Clone`, not `Serialize`, `Debug` redacted.
pub struct Plaintext {
    pub(crate) content: SecretBytes,
    pub(crate) aad: Option<Vec<u8>>,
}

/// A key that encrypts JWE content-encryption keys under `K`; it carries its JWK's `kid` into the header.
/// Not `Clone`, `Debug` redacted.
pub struct EncryptKey<K: KeyAlg> {
    pub(crate) kid: Option<Kid>,
    pub(crate) material: Public,
    pub(crate) alg: PhantomData<K>,
}

/// A key that decrypts JWEs under `K` and nothing else. Not `Clone`, not `Serialize`, `Debug` redacted.
pub struct DecryptKey<K: KeyAlg> {
    pub(crate) material: Private,
    pub(crate) alg: PhantomData<K>,
}
