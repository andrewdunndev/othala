//! WebAuthn Level 3 relying-party ceremonies and verifier.
//!
//! Sans-IO: time is an argument, randomness is `base::Entropy`, and every
//! store write leaves as one `base::Effect` over [`Key`] and [`Record`].
//! A verdict leaves its [`Pending`] only against the store's `Receipt`.
#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod attestation;

mod authdata;

mod cbor;

mod client_data;

mod cose;

mod error;

mod extensions;

mod json;

mod options;

mod policy;

mod record;

mod response;

mod trust;

mod verify;

#[cfg(test)]
mod testing;

pub use cose::CoseAlgorithm;

pub use error::{Error, ErrorKind, SpecStep};

pub use extensions::{
    AppId, AppIdUsed, Discoverability, LargeBlobOp, LargeBlobOutcome, LargeBlobRequest,
    LargeBlobSupport, PrfEval, PrfOutputs, PrfRequest, PrfResult,
};

pub use json::{RelatedOrigins, Signal, SignalOptions};

pub use options::{
    Allow, Attachment, AuthenticationOptions, Conveyance, CreationOptions, CredentialDescriptor,
    DisplayName, Hint, Mediation, RegistrationOptions, RequestOptions, Requirement, ResidentKey,
    Timeout, Transport, UserEntity, UserHandle, UserName,
};

pub use policy::{
    CounterPolicy, CrossOrigin, KeyEnforcement, Origin, RelyingParty, RelyingPartyBuilder, RpId,
    TrustPolicy, UnsolicitedExtensions,
};

pub use record::{
    Aaguid, AuthenticationCeremony, Credential, CredentialId, Key, Record, RegistrationCeremony,
};

pub use response::{AuthenticationResponse, Lookup, RegistrationResponse};

pub use trust::{
    Attestation, AttestationType, Format, Trust, TrustAnchor, TrustDecision, TrustQuery,
    TrustSource,
};

pub use verify::{
    Assertion, AssertionVerification, Backup, BackupState, Counter, Registered, UserVerification,
};

/// A verdict that is void until settled with its effect's `Receipt`.
pub type Pending<T> = base::Pending<T, Key, Record>;

/// The one store effect this crate emits: ceremony and credential rows only.
pub type Effect = base::Effect<Key, Record>;

/// What a finish returns: the verification result, held until the effect commits; a failure still carries the ceremony row's delete.
pub type Verdict<T> = Pending<Result<T, Error>>;

/// Longest credential id accepted (L3 7.1 step 28).
pub const MAX_CREDENTIAL_ID: usize = 1023;

/// Longest user handle (L3 5.4.3).
pub const MAX_USER_HANDLE: usize = 64;

/// Longest RP ID, in bytes.
pub const MAX_RP_ID: usize = 253;

/// Longest user name, display name or RP name, in bytes.
pub const MAX_NAME: usize = 256;

/// Longest `clientDataJSON`, in bytes.
pub const MAX_CLIENT_DATA_JSON: usize = 16_384;

/// Deepest JSON nesting the `clientDataJSON` reader accepts, apart from the CBOR bound.
pub const MAX_CLIENT_DATA_DEPTH: usize = 8;

/// Longest `attestationObject`, in bytes.
pub const MAX_ATTESTATION_OBJECT: usize = 65_536;

/// Longest assertion `authenticatorData`, in bytes.
pub const MAX_AUTHENTICATOR_DATA: usize = 16_384;

/// Longest assertion signature, in bytes.
pub const MAX_SIGNATURE: usize = 1_024;

/// Deepest CBOR nesting the reader accepts.
pub const MAX_CBOR_DEPTH: usize = 16;

/// Most CBOR data items in one input.
pub const MAX_CBOR_ITEMS: usize = 1_024;

/// Most certificates in an `x5c`, and the longest chain walked.
pub const MAX_X5C: usize = 8;

/// Longest DER certificate, in `x5c` or as a trust anchor.
pub const MAX_CERTIFICATE: usize = 8_192;

/// Most credentials in an allow or exclude list.
pub const MAX_LISTED_CREDENTIALS: usize = 64;

/// Most origins one relying party accepts, top origins included.
pub const MAX_ORIGINS: usize = 32;

/// Longest FIDO AppID, in bytes.
pub const MAX_APP_ID: usize = 2_048;

/// Longest PRF salt, in bytes.
pub const MAX_PRF_SALT: usize = 256;

/// Fewest bits in an RSA modulus, credential or certificate key.
pub const MIN_RSA_BITS: usize = 2_048;

/// Most bits in an RSA modulus, credential or certificate key.
pub const MAX_RSA_BITS: usize = 4_096;

/// Longest large blob, written or read back, in bytes.
pub const MAX_LARGE_BLOB: usize = 65_536;

/// Longest encoded `Record`, in bytes.
pub const MAX_RECORD: usize = 8_192;

/// Longest ceremony timeout, in seconds (the top of the L3 15.1 range).
pub const MAX_TIMEOUT_SECS: u32 = 600;
