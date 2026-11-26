use base::{Digest, Scope, StoreKey};

use crate::{Attempts, RecoveryHash, TotpStep};

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

/// A stored row, as opaque versioned bytes through the codec factor-04 lands.
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
    use base::{Digest, Scope, StoreKey};

    use super::Key;

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
