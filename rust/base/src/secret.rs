use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::b64url::decode_exact;
use crate::{Entropy, Error};

/// A fixed-size secret: no `Display`, `Clone`, `Serialize` or `PartialEq`, and `Debug` redacts.
pub struct Secret<const N: usize>([u8; N]);

/// A secret of runtime length, such as an imported TOTP or HMAC key.
pub struct SecretBytes(Vec<u8>);

/// A SHA-256 digest: safe to store, index and compare.
// Derived equality is not constant-time because a digest is a hash the comparer holds, never a value an attacker can choose.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest([u8; 32]);

/// Ties a ceremony to a browser through the secret it is built from: safe to store, compared in constant time.
#[derive(Clone, Copy, Debug)]
pub struct BrowserBinding(Digest);

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

    /// Decodes presented unpadded base64url of exactly `N` bytes; `Malformed` otherwise.
    pub fn from_b64url(text: &str) -> Result<Self, Error> {
        decode_exact(text).map(Self)
    }

    /// The single greppable read, only under the `expose` feature.
    #[cfg(feature = "expose")]
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

    /// The single greppable read, only under the `expose` feature.
    #[cfg(feature = "expose")]
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

    /// Decodes the text form; `Malformed` unless it is unpadded base64url of 32 bytes.
    pub fn from_b64url(text: &str) -> Result<Self, Error> {
        decode_exact(text).map(Self)
    }

    /// The text form: unpadded base64url, 43 symbols.
    pub fn to_b64url(&self) -> String {
        crate::b64url_encode(&self.0)
    }

    pub(crate) fn of(parts: &[u8]) -> Self {
        Self(Sha256::digest(parts).into())
    }
}

// A labelled SHA-256, so a binding never equals the plain `digest` of the same secret that another record may store.
impl From<&Secret<32>> for BrowserBinding {
    fn from(secret: &Secret<32>) -> Self {
        let hash = Sha256::new()
            .chain_update(b"base browser binding v1")
            .chain_update(secret.0);
        Self(Digest(hash.finalize().into()))
    }
}

impl PartialEq for BrowserBinding {
    fn eq(&self, other: &Self) -> bool {
        self.0.0.as_slice().ct_eq(other.0.0.as_slice()).into()
    }
}

impl Eq for BrowserBinding {}

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
        s.serialize_str(&self.to_b64url())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Text;
        impl serde::de::Visitor<'_> for Text {
            type Value = Digest;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a SHA-256 digest as unpadded base64url")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Digest, E> {
                Digest::from_b64url(v)
                    .map_err(|_| E::custom("not a SHA-256 digest as unpadded base64url"))
            }
        }
        d.deserialize_str(Text)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for BrowserBinding {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for BrowserBinding {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Digest::deserialize(d).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::{BrowserBinding, Digest, Secret, SecretBytes};
    use crate::{Entropy, Error, ErrorKind};
    use alloc::format;
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;
    use sha2::{Digest as _, Sha256};

    struct Counting(u8);

    impl Entropy for Counting {
        fn fill(&mut self, out: &mut [u8]) {
            for b in out.iter_mut() {
                self.0 += 1;
                *b = self.0;
            }
        }
    }

    #[test]
    fn generate_draws_n_bytes() {
        let mut e = Counting(0);
        let s = Secret::<4>::generate(&mut e);
        assert_eq!(e.0, 4);
        assert_eq!(&s.0, &[1, 2, 3, 4]);
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

    #[cfg(feature = "expose")]
    #[test]
    fn exposes_what_it_holds() {
        assert_eq!(SecretBytes::new(vec![1, 2]).expose(), &[1, 2]);
        assert_eq!(Secret::new([3, 4]).expose(), &[3, 4]);
    }

    #[test]
    fn from_b64url_takes_exactly_n() {
        let s = Secret::<4>::from_b64url("AQIDBA");
        assert!(s.is_ok_and(|s| s.ct_eq(&Secret::new([1, 2, 3, 4]))));
        for wrong in ["AQID", "AQIDBAU", "AQIDBB", "AQIDBA=="] {
            assert_eq!(
                Secret::<4>::from_b64url(wrong).map(|_| ()),
                Err(Error::new(ErrorKind::Malformed)),
                "{wrong}"
            );
        }
    }

    #[test]
    fn digest_text_round_trips() {
        let d = Secret::new([9u8; 8]).digest();
        let text = d.to_b64url();
        assert_eq!(text.len(), 43);
        assert_eq!(Digest::from_b64url(&text), Ok(d));
        assert!(Digest::from_b64url(&text[..42]).is_err());
        assert!(Digest::from_b64url("AQIDBA").is_err());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn digest_serde_is_text() {
        let d = Digest::from_bytes([0xfb; 32]);
        let json = serde_json::to_string(&d).map_err(|e| e.to_string());
        let want = alloc::format!("\"{}\"", "-_v7".repeat(10) + "-_s");
        assert_eq!(json.as_deref(), Ok(want.as_str()));
        assert_eq!(serde_json::from_str::<Digest>(&want).ok(), Some(d));
        let e = serde_json::from_str::<Digest>("[1,2]")
            .map_or_else(|e| e.to_string(), |_| "decoded".into());
        assert!(
            e.contains("expected a SHA-256 digest as unpadded base64url"),
            "{e}"
        );
        let presented = "supersecretpresentedtoken";
        let e = serde_json::from_str::<Digest>(&format!("\"{presented}\""))
            .map_or_else(|e| e.to_string(), |_| "decoded".into());
        assert!(
            e.contains("not a SHA-256 digest as unpadded base64url"),
            "{e}"
        );
        assert!(!e.contains(presented), "the error echoes its input: {e}");
    }

    #[test]
    fn browser_binding_is_labelled_sha256() {
        let (a, b) = (Secret::new([5u8; 32]), Secret::new([6u8; 32]));
        let want: [u8; 32] =
            Sha256::digest([&b"base browser binding v1"[..], &[5; 32]].concat()).into();
        assert_eq!(BrowserBinding::from(&a).0, Digest::from_bytes(want));
        assert_eq!(
            BrowserBinding::from(&a),
            BrowserBinding::from(&Secret::new([5; 32]))
        );
        assert_ne!(BrowserBinding::from(&a).0, a.digest());
        assert_ne!(BrowserBinding::from(&a), BrowserBinding::from(&b));
    }

    #[test]
    fn browser_binding_eq_sees_the_last_byte() {
        let mut bytes = [7u8; 32];
        let a = BrowserBinding(Digest::from_bytes(bytes));
        bytes[31] ^= 1;
        assert_ne!(a, BrowserBinding(Digest::from_bytes(bytes)));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn browser_binding_serde_is_digest_text() {
        let binding = BrowserBinding::from(&Secret::new([5u8; 32]));
        let json = serde_json::to_string(&binding).map_err(|e| e.to_string());
        let want = serde_json::to_string(&binding.0).map_err(|e| e.to_string());
        assert_eq!(json, want);
        let back = json
            .ok()
            .and_then(|j| serde_json::from_str::<BrowserBinding>(&j).ok());
        assert_eq!(back, Some(binding));
        assert!(serde_json::from_str::<BrowserBinding>("\"AQIDBA\"").is_err());
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
