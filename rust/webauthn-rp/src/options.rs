//! User entities, per-call ceremony options and the client options they produce (R11 to R14).
use core::fmt;

use base::Entropy;

use crate::cose::CoseAlgorithm;
use crate::error::{Error, ErrorKind};
use crate::extensions::{AuthenticationExtensions, RegistrationExtensions};
use crate::policy::RpId;
use crate::record::CredentialId;
use crate::trust::Format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::{MAX_NAME, MAX_TIMEOUT_SECS, MAX_USER_HANDLE};

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
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "read by the serializer of webauthn-15")
)]
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

impl UserHandle {
    /// Draw a new handle: 32 bytes of `Entropy`.
    pub fn generate(e: &mut impl Entropy) -> Self {
        let mut bytes = [0; 32];
        e.fill(&mut bytes);
        Self(bytes.to_vec())
    }

    /// Read a handle back from storage; empty is `Malformed`, longer than `MAX_USER_HANDLE` is `TooLarge`.
    pub fn from_stored(bytes: &[u8]) -> Result<Self, Error> {
        bounded(bytes.len(), MAX_USER_HANDLE, 1)?;
        Ok(Self(bytes.to_vec()))
    }

    /// The handle's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// `least` to `most` inclusive: past `most` is `TooLarge`, short of `least` is `Malformed`
fn bounded(len: usize, most: usize, least: usize) -> Result<(), Error> {
    if len > most {
        Err(Error::new(ErrorKind::TooLarge))
    } else if len < least {
        Err(Error::new(ErrorKind::Malformed))
    } else {
        Ok(())
    }
}

impl UserName {
    /// Parse a user name.
    pub fn parse(text: &str) -> Result<Self, Error> {
        bounded(text.len(), MAX_NAME, 1).map(|()| Self(text.to_string()))
    }

    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl DisplayName {
    /// Parse a display name.
    pub fn parse(text: &str) -> Result<Self, Error> {
        bounded(text.len(), MAX_NAME, 0).map(|()| Self(text.to_string()))
    }

    /// The name as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl UserEntity {
    /// Name the user.
    pub fn new(handle: UserHandle, name: UserName, display_name: DisplayName) -> Self {
        Self {
            handle,
            name,
            display_name,
        }
    }

    /// The user's handle.
    pub fn handle(&self) -> &UserHandle {
        &self.handle
    }
}

impl fmt::Debug for UserName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UserName(redacted)")
    }
}

impl fmt::Debug for DisplayName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DisplayName(redacted)")
    }
}

impl fmt::Debug for UserEntity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UserEntity(redacted)")
    }
}

const TRANSPORTS: [(Transport, &str); 6] = [
    (Transport::Usb, "usb"),
    (Transport::Nfc, "nfc"),
    (Transport::Ble, "ble"),
    (Transport::SmartCard, "smart-card"),
    (Transport::Hybrid, "hybrid"),
    (Transport::Internal, "internal"),
];

impl Transport {
    /// The L3 5.8.4 name.
    pub fn as_str(&self) -> &'static str {
        TRANSPORTS
            .iter()
            .find(|(t, _)| t == self)
            .map_or("", |(_, name)| name)
    }

    /// Read a name back; any other text is `Malformed`.
    pub fn parse(text: &str) -> Result<Self, Error> {
        TRANSPORTS
            .iter()
            .find(|(_, name)| *name == text)
            .map(|(t, _)| *t)
            .ok_or(Error::new(ErrorKind::Malformed))
    }
}

impl CredentialDescriptor {
    /// Name a credential and the transports it was registered with; a repeated transport is kept once.
    pub fn new(id: CredentialId, transports: &[Transport]) -> Self {
        let mut kept: Vec<Transport> = Vec::new();
        for t in transports {
            if !kept.contains(t) {
                kept.push(*t);
            }
        }
        Self {
            id,
            transports: kept,
        }
    }

    /// The credential id.
    pub fn id(&self) -> &CredentialId {
        &self.id
    }

    /// The transports, without repeats.
    pub fn transports(&self) -> &[Transport] {
        &self.transports
    }
}

impl Timeout {
    /// Zero is `Malformed`, past `MAX_TIMEOUT_SECS` is `TooLarge`.
    pub fn from_secs(secs: u32) -> Result<Self, Error> {
        match secs {
            0 => Err(Error::new(ErrorKind::Malformed)),
            1..=MAX_TIMEOUT_SECS => Ok(Self(secs)),
            _ => Err(Error::new(ErrorKind::TooLarge)),
        }
    }

    /// The timeout in seconds.
    pub fn secs(&self) -> u32 {
        self.0
    }
}

impl AuthenticationOptions {
    /// User verification is always chosen by the caller.
    pub fn new(user_verification: Requirement, timeout: Timeout) -> Self {
        Self {
            user_verification,
            timeout,
            hints: Vec::new(),
            extensions: AuthenticationExtensions::default(),
        }
    }

    /// Add a user-agent hint, in order; a repeat is ignored.
    pub fn hint(mut self, hint: Hint) -> Self {
        if !self.hints.contains(&hint) {
            self.hints.push(hint);
        }
        self
    }
}

impl RegistrationOptions {
    /// User verification and resident key are always chosen by the caller.
    pub fn new(
        user_verification: Requirement,
        resident_key: ResidentKey,
        timeout: Timeout,
    ) -> Self {
        Self {
            user_verification,
            resident_key,
            timeout,
            algorithms: Vec::new(),
            attachment: None,
            conveyance: Conveyance::None,
            formats: Vec::new(),
            hints: Vec::new(),
            mediation: Mediation::Optional,
            extensions: RegistrationExtensions::default(),
        }
    }

    /// Offer one more algorithm, in preference order (a repeat is ignored); with none offered, ES256, EdDSA, ES384 and RS256.
    pub fn algorithm(mut self, alg: CoseAlgorithm) -> Self {
        if !self.algorithms.contains(&alg) {
            self.algorithms.push(alg);
        }
        self
    }

    /// Ask for an authenticator attachment.
    pub fn attachment(mut self, attachment: Attachment) -> Self {
        self.attachment = Some(attachment);
        self
    }

    /// Set the attestation conveyance preference; the default is `Conveyance::None`.
    pub fn attestation(mut self, conveyance: Conveyance) -> Self {
        self.conveyance = conveyance;
        self
    }

    /// Prefer one more attestation format (`attestationFormats`), in order; a repeat is ignored.
    pub fn attestation_format(mut self, format: Format) -> Self {
        if !self.formats.contains(&format) {
            self.formats.push(format);
        }
        self
    }

    /// Add a user-agent hint, in order; a repeat is ignored.
    pub fn hint(mut self, hint: Hint) -> Self {
        if !self.hints.contains(&hint) {
            self.hints.push(hint);
        }
        self
    }

    /// Set the mediation the client will be called with.
    pub fn mediation(mut self, mediation: Mediation) -> Self {
        self.mediation = mediation;
        self
    }
}

impl fmt::Debug for CreationOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreationOptions")
            .field("rp_id", &self.rp_id)
            .field("exclude", &self.exclude)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::vec;

    use super::{
        AuthenticationOptions, CredentialDescriptor, DisplayName, Hint, Requirement, Timeout,
        Transport, UserEntity, UserHandle, UserName,
    };
    use crate::error::ErrorKind;
    use crate::record::CredentialId;
    use crate::{MAX_NAME, MAX_TIMEOUT_SECS, MAX_USER_HANDLE};

    fn kind<T>(r: Result<T, crate::error::Error>) -> Option<ErrorKind> {
        r.err().map(|e| e.kind())
    }

    #[test]
    fn user_handles_are_32_drawn_bytes_or_1_to_64_stored() {
        let handle = UserHandle::generate(&mut testkit::seeded(1));
        assert_eq!(handle.as_bytes().len(), 32);
        assert_ne!(handle, UserHandle::generate(&mut testkit::seeded(2)));
        assert_eq!(handle, UserHandle::generate(&mut testkit::seeded(1)));
        assert_eq!(
            kind(UserHandle::from_stored(&[])),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            UserHandle::from_stored(&[7]).map(|h| h.as_bytes().to_vec()),
            Ok(vec![7])
        );
        assert!(UserHandle::from_stored(&[0; MAX_USER_HANDLE]).is_ok());
        assert_eq!(
            kind(UserHandle::from_stored(&[0; MAX_USER_HANDLE + 1])),
            Some(ErrorKind::TooLarge)
        );
    }

    #[test]
    fn names_are_bounded_and_never_printed() {
        assert_eq!(kind(UserName::parse("")), Some(ErrorKind::Malformed));
        assert_eq!(UserName::parse("a").as_ref().map(UserName::as_str), Ok("a"));
        assert!(UserName::parse(&"a".repeat(MAX_NAME)).is_ok());
        assert_eq!(
            kind(UserName::parse(&"a".repeat(MAX_NAME + 1))),
            Some(ErrorKind::TooLarge)
        );
        assert_eq!(
            DisplayName::parse("").as_ref().map(DisplayName::as_str),
            Ok("")
        );
        assert_eq!(
            DisplayName::parse("Ada").as_ref().map(DisplayName::as_str),
            Ok("Ada")
        );
        assert!(DisplayName::parse(&"a".repeat(MAX_NAME)).is_ok());
        assert_eq!(
            kind(DisplayName::parse(&"a".repeat(MAX_NAME + 1))),
            Some(ErrorKind::TooLarge)
        );
        let entity = UserEntity::new(
            UserHandle(vec![1]),
            UserName("secret-name".into()),
            DisplayName("secret-display".into()),
        );
        assert_eq!(entity.handle().as_bytes(), &[1]);
        let shown = format!("{entity:?} {:?} {:?}", entity.name, entity.display_name);
        assert!(!shown.contains("secret"), "{shown}");
        assert_eq!(
            shown,
            "UserEntity(redacted) UserName(redacted) DisplayName(redacted)"
        );
    }

    #[test]
    fn transports_have_their_l3_names() {
        let all = [
            Transport::Usb,
            Transport::Nfc,
            Transport::Ble,
            Transport::SmartCard,
            Transport::Hybrid,
            Transport::Internal,
        ];
        let names = ["usb", "nfc", "ble", "smart-card", "hybrid", "internal"];
        for (t, name) in all.into_iter().zip(names) {
            assert_eq!(t.as_str(), name);
            assert_eq!(Transport::parse(name), Ok(t));
        }
        for other in ["", "USB", "usb ", "cable"] {
            assert_eq!(kind(Transport::parse(other)), Some(ErrorKind::Malformed));
        }
    }

    #[test]
    fn descriptors_keep_each_transport_once_in_order() -> Result<(), crate::error::Error> {
        let d = CredentialDescriptor::new(
            CredentialId::from_bytes(b"c")?,
            &[
                Transport::Nfc,
                Transport::Usb,
                Transport::Nfc,
                Transport::Usb,
                Transport::Ble,
            ],
        );
        assert_eq!(
            d.transports(),
            &[Transport::Nfc, Transport::Usb, Transport::Ble]
        );
        assert_eq!(d.id().as_bytes(), b"c");
        Ok(())
    }

    #[test]
    fn timeouts_are_1_to_the_maximum() {
        assert_eq!(kind(Timeout::from_secs(0)), Some(ErrorKind::Malformed));
        assert_eq!(Timeout::from_secs(1).map(|t| t.secs()), Ok(1));
        assert_eq!(
            Timeout::from_secs(MAX_TIMEOUT_SECS).map(|t| t.secs()),
            Ok(MAX_TIMEOUT_SECS)
        );
        assert_eq!(
            kind(Timeout::from_secs(MAX_TIMEOUT_SECS + 1)),
            Some(ErrorKind::TooLarge)
        );
    }

    #[test]
    fn authentication_options_collect_hints_in_order() -> Result<(), crate::error::Error> {
        let o = AuthenticationOptions::new(Requirement::Required, Timeout::from_secs(5)?)
            .hint(Hint::Hybrid)
            .hint(Hint::SecurityKey);
        assert_eq!(
            (o.user_verification, o.timeout.secs(), o.hints),
            (
                Requirement::Required,
                5,
                vec![Hint::Hybrid, Hint::SecurityKey]
            )
        );
        Ok(())
    }

    #[test]
    fn registration_options_collect_in_order() -> Result<(), crate::error::Error> {
        use crate::cose::CoseAlgorithm;
        use crate::options::{Attachment, Conveyance, Mediation, RegistrationOptions, ResidentKey};
        use crate::trust::Format;
        let o = RegistrationOptions::new(
            Requirement::Required,
            ResidentKey::Discouraged,
            Timeout::from_secs(5)?,
        );
        assert_eq!(
            (o.user_verification, o.resident_key, o.timeout.secs()),
            (Requirement::Required, ResidentKey::Discouraged, 5)
        );
        assert_eq!(
            (
                o.algorithms.is_empty(),
                o.attachment,
                o.conveyance,
                o.formats.is_empty(),
                o.hints.is_empty(),
                o.mediation
            ),
            (
                true,
                None,
                Conveyance::None,
                true,
                true,
                Mediation::Optional
            )
        );
        let o = o
            .algorithm(CoseAlgorithm::Rs256)
            .algorithm(CoseAlgorithm::Es256)
            .attachment(Attachment::Platform)
            .attestation(Conveyance::Direct)
            .attestation_format(Format::Packed)
            .attestation_format(Format::None)
            .hint(Hint::Hybrid)
            .hint(Hint::ClientDevice)
            .mediation(Mediation::Conditional);
        assert_eq!(
            o.algorithms,
            vec![CoseAlgorithm::Rs256, CoseAlgorithm::Es256]
        );
        assert_eq!(
            (o.attachment, o.conveyance, o.mediation),
            (
                Some(Attachment::Platform),
                Conveyance::Direct,
                Mediation::Conditional
            )
        );
        assert_eq!(
            (o.formats, o.hints),
            (
                vec![Format::Packed, Format::None],
                vec![Hint::Hybrid, Hint::ClientDevice]
            )
        );
        Ok(())
    }

    #[test]
    fn creation_options_print_no_name() -> Result<(), crate::error::Error> {
        use crate::options::{CreationOptions, RegistrationOptions, ResidentKey};
        use crate::policy::RpId;
        let options = RegistrationOptions::new(
            Requirement::Required,
            ResidentKey::Preferred,
            Timeout::from_secs(5)?,
        );
        let user = UserEntity::new(
            UserHandle(vec![1]),
            UserName("secret-name".into()),
            DisplayName("secret-display".into()),
        );
        let creation = CreationOptions {
            challenge: [7; 32],
            rp_id: RpId::parse("example.org")?,
            rp_name: DisplayName("secret-rp".into()),
            user,
            exclude: vec![],
            options,
        };
        let shown = format!("{creation:?}");
        assert!(
            shown.starts_with("CreationOptions { rp_id: RpId(")
                && shown.contains("example.org")
                && shown.contains("exclude: []"),
            "{shown}"
        );
        assert!(!shown.contains("secret") && !shown.contains('7'), "{shown}");
        Ok(())
    }
}
