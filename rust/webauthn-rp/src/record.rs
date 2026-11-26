//! Store keys and records: opaque versioned bytes, no serde (R15, R21, R140 to R142); bodies with webauthn-04.

use base::Digest;

/// A credential id: 1 to `MAX_CREDENTIAL_ID` bytes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialId(());

/// An authenticator model identifier; authenticated only by an `Anchored` attestation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Aaguid(());

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
pub struct RegistrationCeremony(());

/// What an authentication needs from its start: the challenge's digest, the browser binding, allowed credentials, deadline and requested options. Holds no challenge byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticationCeremony(());

/// A credential record (L3 7.1 step 27).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential(());
