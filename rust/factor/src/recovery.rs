#![expect(dead_code, reason = "fields are read by the bodies factor-08 lands")]

use base::{Digest, SecretBytes};

/// How many codes one generation draws: 1 to 16.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryCount(u8);

/// One 120-bit look-up secret, shown as 24 Crockford base32 symbols in four groups of six; wiped on drop by base.
pub struct RecoveryCode(SecretBytes);

/// The SHA-256 digest of one unused code's bytes; stored under [`crate::Key::Recovery`] of the same digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryHash(Digest);

impl RecoveryHash {
    pub(crate) const fn new(digest: Digest) -> Self {
        Self(digest)
    }

    pub(crate) const fn parts(&self) -> Digest {
        self.0
    }
}

/// A presented code matched an unused one, which the verdict's effect consumes.
#[derive(Debug)]
pub struct RecoveryMatch(());
