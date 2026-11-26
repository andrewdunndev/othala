use alloc::vec::Vec;
use core::fmt;

use base::{Digest, Entropy, Row, SecretBytes};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq;

use crate::{Error, ErrorKind, Key, Pending, Permit, Record, Rejected};

const CODE_BYTES: usize = 15;
const SYMBOLS: usize = 24;
const GROUP: usize = 6;
const MAX_TEXT: usize = 64;
const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const fn err(kind: ErrorKind) -> Error {
    Error { kind }
}

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

impl RecoveryCount {
    /// Accepts 1 to 16.
    pub const fn new(codes: u8) -> Result<Self, Error> {
        match codes {
            1..=16 => Ok(Self(codes)),
            _ => Err(err(ErrorKind::OutOfRange)),
        }
    }
}

/// The value of one Crockford symbol; `I` and `L` read as `1`, `O` as `0`, and case is ignored.
fn value(symbol: u8) -> Option<u32> {
    let symbol = match symbol.to_ascii_uppercase() {
        b'I' | b'L' => b'1',
        b'O' => b'0',
        other => other,
    };
    ALPHABET
        .iter()
        .position(|a| *a == symbol)
        .and_then(|v| u32::try_from(v).ok())
}

fn symbol(value: u32) -> char {
    let at = usize::try_from(value).unwrap_or_default();
    ALPHABET.get(at).copied().map_or('0', char::from)
}

impl RecoveryCode {
    /// Reads the shown text back: case, `-` and spaces are ignored; `TooLarge` over 64 bytes, then `Malformed`
    /// unless 24 symbols remain.
    pub fn parse(text: &str) -> Result<Self, Error> {
        if text.len() > MAX_TEXT {
            return Err(err(ErrorKind::TooLarge));
        }
        let mut symbols = 0;
        let (mut acc, mut bits) = (0u32, 0u32);
        let mut bytes = Vec::with_capacity(CODE_BYTES);
        for b in text.bytes().filter(|b| !matches!(b, b'-' | b' ')) {
            let v = value(b).ok_or(err(ErrorKind::Malformed))?;
            symbols += 1;
            (acc, bits) = ((acc << 5) | v, bits + 5);
            if bits >= 8 {
                bits -= 8;
                bytes.extend(u8::try_from((acc >> bits) & 0xff));
                acc &= (1 << bits) - 1;
            }
        }
        if symbols == SYMBOLS {
            Ok(Self(SecretBytes::new(bytes)))
        } else {
            Err(err(ErrorKind::Malformed))
        }
    }

    /// The text to show once: `XXXXXX-XXXXXX-XXXXXX-XXXXXX`, written on demand from the code.
    pub fn display(&self) -> impl fmt::Display + '_ {
        Shown(&self.0)
    }

    fn digest(&self) -> Digest {
        Digest::from_bytes(Sha256::digest(self.0.expose()).into())
    }

    /// The row this code is stored under: the SHA-256 of its bytes.
    pub fn key(&self) -> Key {
        Key::Recovery(self.digest())
    }
}

struct Shown<'a>(&'a SecretBytes);

impl fmt::Display for Shown<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (mut acc, mut bits, mut shown) = (0u32, 0u32, 0usize);
        for byte in self.0.expose() {
            (acc, bits) = ((acc << 8) | u32::from(*byte), bits + 8);
            while bits >= 5 {
                bits -= 5;
                if shown > 0 && shown % GROUP == 0 {
                    f.write_str("-")?;
                }
                shown += 1;
                fmt::Write::write_char(f, symbol((acc >> bits) & 31))?;
            }
            acc &= (1 << bits) - 1;
        }
        Ok(())
    }
}

impl fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryCode").finish_non_exhaustive()
    }
}

/// `count` fresh codes and the effect that creates one row per code; a repeated draw is `Internal`.
pub fn recovery_generate(
    count: RecoveryCount,
    e: &mut impl Entropy,
) -> Result<Pending<Vec<RecoveryCode>>, Error> {
    let codes: Vec<RecoveryCode> = (0..count.0)
        .map(|_| {
            let mut bytes = [0; CODE_BYTES];
            e.fill(&mut bytes);
            RecoveryCode(SecretBytes::new(bytes.to_vec()))
        })
        .collect();
    let mut effect = crate::Effect::builder(e);
    for code in &codes {
        let row = Record::Recovery(RecoveryHash::new(code.digest()));
        effect = effect.create(code.key(), row, None);
    }
    let effect = effect.build().map_err(|_| err(ErrorKind::Internal))?;
    Ok(Pending::new(codes, effect))
}

/// A match iff `stored` is the row under the code's key; the match consumes it, and every verdict counts.
pub fn recovery_verify(
    permit: Permit,
    code: &RecoveryCode,
    stored: Option<Row<&RecoveryHash>>,
    e: &mut impl Entropy,
) -> Result<Pending<Result<RecoveryMatch, Rejected>>, Error> {
    let key = code.key();
    let held =
        |row: &RecoveryHash| bool::from(code.digest().as_bytes().ct_eq(row.parts().as_bytes()));
    let counted = permit.count(e);
    let (verdict, effect) = match &stored {
        Some(row) if held(row.record()) => (Ok(RecoveryMatch(())), counted.consume(key)),
        Some(row) => (Err(Rejected::Wrong), counted.expect(key, row)),
        None => (Err(Rejected::Wrong), counted.expect_absent(key)),
    };
    let effect = effect.build().map_err(|_| err(ErrorKind::Internal))?;
    Ok(Pending::new(verdict, effect))
}
