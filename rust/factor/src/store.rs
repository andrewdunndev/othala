use alloc::vec::Vec;

use base::{Digest, Scope, StoreKey, UnixTime};

use crate::{Attempts, Error, ErrorKind, RecoveryHash, TotpStep};

const VERSION: u8 = 1;
const MAX_ROW: usize = 64;

/// The rows this crate's effects hold; the host qualifies each with the subject, and stores the authenticators themselves.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Key {
    /// The subject's attempt count, shared by every factor.
    Attempts,
    /// The last TOTP step the subject's authenticator accepted, apart from the row holding its key.
    TotpStep,
    /// One unused recovery code, by the SHA-256 digest of its bytes.
    Recovery(Digest),
}

impl StoreKey for Key {
    fn scope(&self) -> Scope {
        Scope::Subject
    }
}

/// A stored row, as opaque versioned bytes through [`Record::encode`] and `decode`.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    /// Under [`Key::Attempts`].
    Attempts(Attempts),
    /// Under [`Key::TotpStep`].
    TotpStep(TotpStep),
    /// Under [`Key::Recovery`] of its own digest.
    Recovery(RecoveryHash),
}

impl Record {
    /// Version 1: a version byte, a tag byte, then big-endian fields (CONTRACT R5).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_ROW);
        match self {
            Self::Attempts(a) => {
                let (count, last) = a.parts();
                out.extend([VERSION, 0]);
                out.extend(count.to_be_bytes());
                out.extend(last.secs().to_be_bytes());
            }
            Self::TotpStep(s) => {
                out.extend([VERSION, 1]);
                out.extend(s.parts().to_be_bytes());
            }
            Self::Recovery(r) => {
                out.extend([VERSION, 2]);
                out.extend(r.parts().as_bytes());
            }
        }
        out
    }

    /// Reads a stored row; call it only on a store's load path, since an `Attempts` can carry any count.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let malformed = Error {
            kind: ErrorKind::Malformed,
        };
        if bytes.len() > MAX_ROW {
            return Err(Error {
                kind: ErrorKind::TooLarge,
            });
        }
        let record = bytes
            .split_first_chunk::<2>()
            .filter(|([version, _], _)| *version == VERSION)
            .and_then(|([_, tag], body)| match tag {
                0 => {
                    let (count, last) = body.split_first_chunk::<4>()?;
                    Some(Self::Attempts(Attempts::new(
                        u32::from_be_bytes(*count),
                        UnixTime::new(u64::from_be_bytes(*<&[u8; 8]>::try_from(last).ok()?)),
                    )))
                }
                1 => Some(Self::TotpStep(TotpStep::new(u64::from_be_bytes(
                    *<&[u8; 8]>::try_from(body).ok()?,
                )))),
                2 => Some(Self::Recovery(RecoveryHash::new(Digest::from_bytes(
                    *<&[u8; 32]>::try_from(body).ok()?,
                )))),
                _ => None,
            });
        record.ok_or(malformed)
    }
}

/// A verdict that is void until settled with its effect's receipt.
pub type Pending<T> = base::Pending<T, Key, Record>;

/// An effect over one subject's rows.
pub type Effect = base::Effect<Key, Record>;

/// Why a presented secret was refused; the attempt is counted either way, and the host shows both alike.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Rejected {
    /// It does not match.
    Wrong,
    /// It matches only TOTP steps at or before the last one accepted.
    Replayed,
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use base::{Digest, Scope, StoreKey, UnixTime};

    use super::{Key, Record};
    use crate::{Attempts, RecoveryHash, TotpStep};

    fn records() -> [Record; 6] {
        [
            Record::Attempts(Attempts::new(0, UnixTime::new(0))),
            Record::Attempts(Attempts::new(u32::MAX, UnixTime::new(u64::MAX))),
            Record::TotpStep(TotpStep::new(0)),
            Record::TotpStep(TotpStep::new(u64::MAX)),
            Record::Recovery(RecoveryHash::new(Digest::from_bytes([0; 32]))),
            Record::Recovery(RecoveryHash::new(Digest::from_bytes([255; 32]))),
        ]
    }

    #[test]
    fn round_trip() {
        for r in records() {
            assert_eq!(Record::decode(&r.encode()).ok(), Some(r));
        }
        // the fields are big-endian, count before time
        let a = Record::Attempts(Attempts::new(1, UnixTime::new(2)));
        assert_eq!(a.encode(), [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2]);
        let lengths: Vec<usize> = records().iter().map(|r| r.encode().len()).collect();
        assert_eq!(lengths, [14, 14, 10, 10, 34, 34]);
    }

    #[test]
    fn every_key_is_subject() {
        let keys = [
            Key::Attempts,
            Key::TotpStep,
            Key::Recovery(Digest::from_bytes([0; 32])),
        ];
        assert!(keys.iter().all(|k| k.scope() == Scope::Subject));
    }
}
