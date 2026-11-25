use alloc::vec::Vec;
use core::fmt;

use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

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
        let mut bytes = [0; N];
        e.fill(&mut bytes);
        Self(bytes)
    }

    /// Takes ownership of bytes presented by a client or decoded from a host.
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// The single greppable read; confined by lint to the modules a `CONTRACT.md` names.
    pub const fn expose(&self) -> &[u8; N] {
        &self.0
    }

    /// Constant-time equality.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }

    /// SHA-256 of the secret bytes.
    pub fn digest(&self) -> Digest {
        Digest::of(&self.0)
    }
}

impl SecretBytes {
    /// Takes ownership of imported key bytes.
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The single greppable read; confined by lint to the modules a `CONTRACT.md` names.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Constant-time equality over equal lengths; unequal lengths are unequal.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.as_slice().ct_eq(other.0.as_slice()).into()
    }

    /// SHA-256 of the secret bytes.
    pub fn digest(&self) -> Digest {
        Digest::of(&self.0)
    }
}

impl Digest {
    /// A digest decoded from storage.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn of(parts: &[u8]) -> Self {
        Self(Sha256::digest(parts).into())
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret<{N}>(redacted)")
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(redacted)")
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Digest(")?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))?;
        f.write_str(")")
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{Digest, Secret, SecretBytes};
    use crate::Entropy;
    use alloc::format;
    use alloc::vec;
    use alloc::vec::Vec;
    use sha2::{Digest as _, Sha256};

    struct Counting(usize);

    impl Entropy for Counting {
        fn fill(&mut self, out: &mut [u8]) {
            for b in out.iter_mut() {
                self.0 += 1;
                *b = u8::try_from(self.0).unwrap();
            }
        }
    }

    #[test]
    fn generate_draws_n_bytes() {
        let mut e = Counting(0);
        let s = Secret::<4>::generate(&mut e);
        assert_eq!(e.0, 4);
        assert_eq!(s.expose(), &[1, 2, 3, 4]);
    }

    #[test]
    fn ct_eq_compares_every_byte() {
        let base = [7u8; 4];
        assert!(Secret::new(base).ct_eq(&Secret::new(base)));
        assert!(SecretBytes::new(base.to_vec()).ct_eq(&SecretBytes::new(base.to_vec())));
        for i in 0..base.len() {
            let mut other = base;
            other[i] ^= 1;
            assert!(!Secret::new(base).ct_eq(&Secret::new(other)));
            assert!(!SecretBytes::new(base.to_vec()).ct_eq(&SecretBytes::new(other.to_vec())));
        }
        assert!(!SecretBytes::new(vec![7; 4]).ct_eq(&SecretBytes::new(vec![7; 3])));
    }

    #[test]
    fn digest_is_sha256() {
        let bytes = *b"0123456789abcdef0123456789abcdef";
        let want: [u8; 32] = Sha256::digest(bytes).into();
        assert_eq!(Secret::new(bytes).digest(), Digest::from_bytes(want));
        assert_eq!(SecretBytes::new(bytes.to_vec()).digest().as_bytes(), &want);
    }

    #[test]
    fn exposes_what_it_holds() {
        assert_eq!(SecretBytes::new(vec![1, 2]).expose(), &[1, 2]);
        assert_eq!(Secret::new([3, 4]).expose(), &[3, 4]);
    }

    #[test]
    fn digest_debug_is_hex() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xab;
        bytes[31] = 0x01;
        let hex: Vec<_> = format!("{:?}", Digest::from_bytes(bytes)).into_bytes();
        assert_eq!(hex.len(), "Digest()".len() + 64);
        assert!(hex.starts_with(b"Digest(ab00"));
        assert!(hex.ends_with(b"0001)"));
    }
}
