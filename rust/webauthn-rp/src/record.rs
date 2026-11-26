//! Store keys and records: opaque versioned bytes, no serde (R15, R21, R140 to R142); bodies with webauthn-04.

use alloc::vec::Vec;

use base::{Digest, UnixTime};

use crate::cose::CoseKey;
use crate::options::{AuthenticationOptions, RegistrationOptions, Transport, UserHandle};
use crate::trust::Attestation;
use crate::verify::{Backup, UserVerification};

/// A credential id: 1 to `MAX_CREDENTIAL_ID` bytes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialId(pub(crate) Vec<u8>);

/// An authenticator model identifier; authenticated only by an `Anchored` attestation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Aaguid(pub(crate) [u8; 16]);

/// A store key this crate guards; both kinds are `Scope::Global`.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Key {
    /// A ceremony, by the SHA-256 of its challenge.
    Ceremony(Digest),
    /// A credential, by its id: the reservation that makes ids unique across users.
    Credential(CredentialId),
}

/// A stored row: opaque versioned bytes through `encode` and `decode`, no serde.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    /// A registration ceremony awaiting its response.
    Registration(RegistrationCeremony),
    /// An authentication ceremony awaiting its response.
    Authentication(AuthenticationCeremony),
    /// A registered credential.
    Credential(Credential),
}

/// What a registration needs from its start: the challenge's digest, user, deadline and requested options. Holds no challenge byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationCeremony {
    pub(crate) challenge: Digest,
    pub(crate) browser: Digest,
    pub(crate) deadline: UnixTime,
    pub(crate) user: UserHandle,
    pub(crate) options: RegistrationOptions,
}

/// What an authentication needs from its start: the challenge's digest, the browser binding, allowed credentials, deadline and requested options. Holds no challenge byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticationCeremony {
    pub(crate) challenge: Digest,
    pub(crate) browser: Digest,
    pub(crate) deadline: UnixTime,
    pub(crate) user: Option<UserHandle>,
    pub(crate) allowed: Vec<Digest>,
    pub(crate) options: AuthenticationOptions,
}

/// A credential record (L3 7.1 step 27).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    pub(crate) id: CredentialId,
    pub(crate) public_key: CoseKey,
    pub(crate) sign_count: u32,
    pub(crate) uv_initialized: UserVerification,
    pub(crate) transports: Vec<Transport>,
    pub(crate) backup: Backup,
    pub(crate) user: UserHandle,
    pub(crate) aaguid: Aaguid,
    pub(crate) attestation: Attestation,
}
