//! User entities, per-call ceremony options and the client options they produce (R11 to R14); bodies with webauthn-04 and webauthn-05.

use crate::cose::CoseAlgorithm;
use crate::extensions::{AuthenticationExtensions, RegistrationExtensions};
use crate::policy::RpId;
use crate::record::CredentialId;
use crate::trust::Format;
use alloc::string::String;
use alloc::vec::Vec;

/// An opaque user handle: 32 bytes from `Entropy`, or a stored handle read back.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserHandle(pub(crate) Vec<u8>);

/// A user name for the account selector; non-empty, at most `MAX_NAME` bytes. `Debug` prints no name. PRECIS profiles are the host's (N18).
#[derive(Clone, PartialEq, Eq)]
pub struct UserName(pub(crate) String);

/// A display name, for a user or for the relying party; at most `MAX_NAME` bytes. `Debug` prints no name.
#[derive(Clone, PartialEq, Eq)]
pub struct DisplayName(pub(crate) String);

/// The user a registration creates a credential for (`PublicKeyCredentialUserEntity`). `Debug` prints no name.
#[derive(Clone, PartialEq, Eq)]
pub struct UserEntity {
    pub(crate) handle: UserHandle,
    pub(crate) name: UserName,
    pub(crate) display_name: DisplayName,
}

/// `userVerification`: `required`, `preferred` or `discouraged`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Requirement {
    /// `required`.
    Required,
    /// `preferred`.
    Preferred,
    /// `discouraged`.
    Discouraged,
}

/// `residentKey`: a type apart from `Requirement`, so the two `RegistrationOptions::new` arguments cannot swap.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResidentKey {
    /// `required`.
    Required,
    /// `preferred`.
    Preferred,
    /// `discouraged`.
    Discouraged,
}

/// `authenticatorAttachment`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attachment {
    /// `platform`.
    Platform,
    /// `cross-platform`.
    CrossPlatform,
}

/// Attestation conveyance preference.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Conveyance {
    /// `none`.
    None,
    /// `indirect`.
    Indirect,
    /// `direct`.
    Direct,
    /// `enterprise`.
    Enterprise,
}

/// A user-agent hint (L3 5.8.8).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hint {
    /// `security-key`.
    SecurityKey,
    /// `client-device`.
    ClientDevice,
    /// `hybrid`.
    Hybrid,
}

/// How the client is asked to mediate a registration.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mediation {
    /// The default: the UP flag is required.
    Optional,
    /// `conditional`: the UP flag is not required (L3 7.1 step 15).
    Conditional,
}

/// An authenticator transport; its L3 5.8.4 name is its stable encoding.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Transport {
    /// `usb`.
    Usb,
    /// `nfc`.
    Nfc,
    /// `ble`.
    Ble,
    /// `smart-card`.
    SmartCard,
    /// `hybrid`.
    Hybrid,
    /// `internal`.
    Internal,
}

/// A credential named in an allow or exclude list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialDescriptor {
    pub(crate) id: CredentialId,
    pub(crate) transports: Vec<Transport>,
}

/// Which credentials an authentication ceremony accepts (L3 7.2 steps 5-6).
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub enum Allow<'a> {
    /// The user is known: only this user's credentials, and of those only the listed ones when the list is not empty.
    User {
        /// The identified user.
        user: &'a UserHandle,
        /// `allowCredentials`.
        credentials: &'a [CredentialDescriptor],
    },
    /// Usernameless: any credential whose response carries its user handle.
    Discoverable,
}

/// A ceremony timeout, 1 to `MAX_TIMEOUT_SECS` seconds; the ceremony's deadline is `now` plus this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timeout(pub(crate) u32);

/// Per-call registration options.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationOptions {
    pub(crate) user_verification: Requirement,
    pub(crate) resident_key: ResidentKey,
    pub(crate) timeout: Timeout,
    pub(crate) algorithms: Vec<CoseAlgorithm>,
    pub(crate) attachment: Option<Attachment>,
    pub(crate) conveyance: Conveyance,
    pub(crate) formats: Vec<Format>,
    pub(crate) hints: Vec<Hint>,
    pub(crate) mediation: Mediation,
    pub(crate) extensions: RegistrationExtensions,
}

/// Per-call authentication options.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticationOptions {
    pub(crate) user_verification: Requirement,
    pub(crate) timeout: Timeout,
    pub(crate) hints: Vec<Hint>,
    pub(crate) extensions: AuthenticationExtensions,
}

/// `PublicKeyCredentialCreationOptionsJSON` (L3 5.1.8), for the client; serialized under `serde`.
#[derive(Clone)]
#[expect(dead_code, reason = "read by the serializer of webauthn-15")]
pub struct CreationOptions {
    pub(crate) challenge: [u8; 32],
    pub(crate) rp_id: RpId,
    pub(crate) rp_name: DisplayName,
    pub(crate) user: UserEntity,
    pub(crate) exclude: Vec<CredentialDescriptor>,
    pub(crate) options: RegistrationOptions,
}

/// `PublicKeyCredentialRequestOptionsJSON` (L3 5.1.9), for the client; serialized under `serde`.
#[derive(Clone, Debug)]
#[expect(dead_code, reason = "read by the serializer of webauthn-15")]
pub struct RequestOptions {
    pub(crate) challenge: [u8; 32],
    pub(crate) rp_id: RpId,
    pub(crate) allow: Vec<CredentialDescriptor>,
    pub(crate) options: AuthenticationOptions,
}
