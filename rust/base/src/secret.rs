use alloc::vec::Vec;
use core::fmt;

use crate::Entropy;

/// A fixed-size secret: no `Display`, `Clone`, `Serialize` or `PartialEq`, and `Debug` redacts.
pub struct Secret<const N: usize>([u8; N]);

/// A secret of runtime length, such as an imported TOTP or HMAC key.
pub struct SecretBytes(Vec<u8>);

/// A SHA-256 digest: safe to store, index and compare.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest([u8; 32]);

impl<const N: usize> Secret<N> {
    /// Draws `N` bytes from `e`.
    pub fn generate(e: &mut impl Entropy) -> Self {
        todo!()
    }

    /// Takes ownership of bytes presented by a client or decoded from a host.
    pub fn new(bytes: [u8; N]) -> Self {
        todo!()
    }

    /// The single greppable read; confined by lint to the modules a `CONTRACT.md` names.
    pub fn expose(&self) -> &[u8; N] {
        todo!()
    }

    /// Constant-time equality.
    pub fn ct_eq(&self, other: &Self) -> bool {
        todo!()
    }

    /// SHA-256 of the secret bytes.
    pub fn digest(&self) -> Digest {
        todo!()
    }
}

impl SecretBytes {
    /// Takes ownership of imported key bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        todo!()
    }

    /// The single greppable read; confined by lint to the modules a `CONTRACT.md` names.
    pub fn expose(&self) -> &[u8] {
        todo!()
    }

    /// Constant-time equality over equal lengths; unequal lengths are unequal.
    pub fn ct_eq(&self, other: &Self) -> bool {
        todo!()
    }

    /// SHA-256 of the secret bytes.
    pub fn digest(&self) -> Digest {
        todo!()
    }
}

impl Digest {
    /// A digest decoded from storage.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        todo!()
    }

    /// The digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        todo!()
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        todo!()
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        todo!()
    }
}

impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        todo!()
    }
}
