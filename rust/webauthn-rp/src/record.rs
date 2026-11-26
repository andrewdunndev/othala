//! Store keys and records: opaque versioned bytes, no serde (R15, R21, R140 to R142).
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use base::{BrowserBinding, Digest, Row, Scope, StoreKey, UnixTime};

use crate::cose::{CoseAlgorithm, CoseKey};
use crate::error::{Error, ErrorKind};
use crate::extensions::{
    AppId, AuthenticationExtensions, LargeBlobOp, LargeBlobRequest, PrfEval, PrfRequest,
    RegistrationExtensions,
};
use crate::options::{
    Attachment, AuthenticationOptions, Conveyance, CredentialDescriptor, Hint, Mediation,
    RegistrationOptions, Requirement, ResidentKey, Timeout, Transport, UserHandle,
};
use crate::trust::{Attestation, AttestationType, Format, Trust};
use crate::verify::{Backup, BackupState, UserVerification};
use crate::{MAX_CREDENTIAL_ID, MAX_RECORD};

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

impl CredentialId {
    /// Empty is `Malformed`, longer than `MAX_CREDENTIAL_ID` is `TooLarge`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        match bytes.len() {
            0 => Err(Error::new(ErrorKind::Malformed)),
            1..=MAX_CREDENTIAL_ID => Ok(Self(bytes.to_vec())),
            _ => Err(Error::new(ErrorKind::TooLarge)),
        }
    }

    /// The id's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Aaguid {
    /// From its 16 bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Its 16 bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl StoreKey for Key {
    fn scope(&self) -> Scope {
        Scope::Global
    }
}

/// The digest a ceremony row keeps of a browser binding, which base hands out only as `Debug` text without its `serde` feature.
pub(crate) fn browser_digest(binding: &BrowserBinding) -> Result<Digest, Error> {
    let text = format!("{binding:?}");
    let hex = text
        .strip_prefix("BrowserBinding(Digest(")
        .and_then(|t| t.strip_suffix("))"))
        .unwrap_or("");
    let nibble = |c: &[u8; 2]| {
        c.iter().try_fold(0u8, |n, b| {
            Some((n << 4) + u8::try_from(char::from(*b).to_digit(16)?).ok()?)
        })
    };
    let bytes: Option<Vec<u8>> = hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(nibble)
        .collect();
    match (hex.len(), bytes.and_then(|b| <[u8; 32]>::try_from(b).ok())) {
        (64, Some(digest)) => Ok(Digest::from_bytes(digest)),
        _ => Err(Error::new(ErrorKind::Corrupt)),
    }
}

const VERSION: u8 = 1;
const REGISTRATION: u8 = 0;
const AUTHENTICATION: u8 = 1;
const CREDENTIAL: u8 = 2;
const REQUIREMENTS: [Requirement; 3] = [
    Requirement::Required,
    Requirement::Preferred,
    Requirement::Discouraged,
];
const RESIDENT_KEYS: [ResidentKey; 3] = [
    ResidentKey::Required,
    ResidentKey::Preferred,
    ResidentKey::Discouraged,
];
const ATTACHMENTS: [Attachment; 2] = [Attachment::Platform, Attachment::CrossPlatform];
const CONVEYANCES: [Conveyance; 4] = [
    Conveyance::None,
    Conveyance::Indirect,
    Conveyance::Direct,
    Conveyance::Enterprise,
];
const HINTS: [Hint; 3] = [Hint::SecurityKey, Hint::ClientDevice, Hint::Hybrid];
const MEDIATIONS: [Mediation; 2] = [Mediation::Optional, Mediation::Conditional];
const TRANSPORTS: [Transport; 6] = [
    Transport::Usb,
    Transport::Nfc,
    Transport::Ble,
    Transport::SmartCard,
    Transport::Hybrid,
    Transport::Internal,
];
const ALGORITHMS: [CoseAlgorithm; 4] = [
    CoseAlgorithm::Es256,
    CoseAlgorithm::Es384,
    CoseAlgorithm::EdDsa,
    CoseAlgorithm::Rs256,
];
const FORMATS: [Format; 6] = [
    Format::None,
    Format::Packed,
    Format::Tpm,
    Format::AndroidKey,
    Format::Apple,
    Format::FidoU2f,
];
const KINDS: [AttestationType; 6] = [
    AttestationType::None,
    AttestationType::SelfAttestation,
    AttestationType::Basic,
    AttestationType::AttCa,
    AttestationType::AnonCa,
    AttestationType::Uncertain,
];
const TRUSTS: [Trust; 2] = [Trust::Anchored, Trust::Unanchored];
const LARGE_BLOBS: [LargeBlobRequest; 2] =
    [LargeBlobRequest::Required, LargeBlobRequest::Preferred];

// each table's order is its stable encoding
fn put_pick<T: PartialEq>(out: &mut Vec<u8>, table: &[T], value: &T) {
    out.push(
        table
            .iter()
            .position(|t| t == value)
            .and_then(|i| u8::try_from(i).ok())
            .unwrap_or(u8::MAX),
    );
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn put_opt<T>(out: &mut Vec<u8>, value: Option<&T>, put: impl FnOnce(&mut Vec<u8>, &T)) {
    out.push(u8::from(value.is_some()));
    if let Some(v) = value {
        put(out, v);
    }
}

// a list length is one byte; a longer list is refused, not clamped
fn put_list<T>(
    out: &mut Vec<u8>,
    values: &[T],
    put: impl Fn(&mut Vec<u8>, &T),
) -> Result<(), Error> {
    out.push(u8::try_from(values.len()).map_err(|_| Error::new(ErrorKind::TooLarge))?);
    values.iter().for_each(|v| put(out, v));
    Ok(())
}

fn put_eval(out: &mut Vec<u8>, eval: &PrfEval) {
    put_bytes(out, &eval.first);
    put_opt(out, eval.second.as_ref(), |o, s| put_bytes(o, s));
}

fn put_key(out: &mut Vec<u8>, key: &CoseKey) {
    put_pick(out, &ALGORITHMS, &key.algorithm());
    match key {
        CoseKey::Es256 { x, y } => [x.as_slice(), y]
            .iter()
            .for_each(|c| out.extend_from_slice(c)),
        CoseKey::Es384 { x, y } => [x.as_slice(), y]
            .iter()
            .for_each(|c| out.extend_from_slice(c)),
        CoseKey::EdDsa(point) => out.extend_from_slice(point),
        CoseKey::Rs256 { n, e } => [n, e].iter().for_each(|c| put_bytes(out, c)),
    }
}

fn put_registration_options(out: &mut Vec<u8>, o: &RegistrationOptions) -> Result<(), Error> {
    put_pick(out, &REQUIREMENTS, &o.user_verification);
    put_pick(out, &RESIDENT_KEYS, &o.resident_key);
    out.extend_from_slice(&o.timeout.0.to_be_bytes());
    put_list(out, &o.algorithms, |o, a| put_pick(o, &ALGORITHMS, a))?;
    put_opt(out, o.attachment.as_ref(), |o, a| {
        put_pick(o, &ATTACHMENTS, a)
    });
    put_pick(out, &CONVEYANCES, &o.conveyance);
    put_list(out, &o.formats, |o, f| put_pick(o, &FORMATS, f))?;
    put_list(out, &o.hints, |o, h| put_pick(o, &HINTS, h))?;
    put_pick(out, &MEDIATIONS, &o.mediation);
    let e = &o.extensions;
    out.push(u8::from(e.cred_props));
    put_opt(out, e.prf.as_ref(), |o, p| match p {
        PrfRequest::Enable => o.push(0),
        PrfRequest::Eval(eval) => {
            o.push(1);
            put_eval(o, eval);
        }
    });
    put_opt(out, e.large_blob.as_ref(), |o, l| {
        put_pick(o, &LARGE_BLOBS, l)
    });
    put_opt(out, e.app_id_exclude.as_ref(), |o, a| {
        put_bytes(o, a.0.as_bytes())
    });
    Ok(())
}

fn put_authentication_options(out: &mut Vec<u8>, o: &AuthenticationOptions) -> Result<(), Error> {
    put_pick(out, &REQUIREMENTS, &o.user_verification);
    out.extend_from_slice(&o.timeout.0.to_be_bytes());
    put_list(out, &o.hints, |o, h| put_pick(o, &HINTS, h))?;
    let e = &o.extensions;
    put_opt(out, e.app_id.as_ref(), |o, a| put_bytes(o, a.0.as_bytes()));
    put_opt(out, e.prf.as_ref(), put_eval);
    put_list(out, &e.prf_by_credential, |o, (id, eval)| {
        put_bytes(o, &id.0);
        put_eval(o, eval);
    })?;
    put_opt(out, e.large_blob.as_ref(), |o, l| match l {
        LargeBlobOp::Read => o.push(0),
        LargeBlobOp::Write(blob) => {
            o.push(1);
            put_bytes(o, blob);
        }
    });
    Ok(())
}

impl Record {
    /// The row's bytes, version-tagged; a list past 255 entries is `TooLarge`.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = alloc::vec![VERSION];
        match self {
            Self::Registration(c) => {
                out.push(REGISTRATION);
                out.extend_from_slice(c.challenge.as_bytes());
                out.extend_from_slice(c.browser.as_bytes());
                out.extend_from_slice(&c.deadline.secs().to_be_bytes());
                put_bytes(&mut out, &c.user.0);
                put_registration_options(&mut out, &c.options)?;
            }
            Self::Authentication(c) => {
                out.push(AUTHENTICATION);
                out.extend_from_slice(c.challenge.as_bytes());
                out.extend_from_slice(c.browser.as_bytes());
                out.extend_from_slice(&c.deadline.secs().to_be_bytes());
                put_opt(&mut out, c.user.as_ref(), |o, u| put_bytes(o, &u.0));
                put_list(&mut out, &c.allowed, |o, d| {
                    o.extend_from_slice(d.as_bytes())
                })?;
                put_authentication_options(&mut out, &c.options)?;
            }
            Self::Credential(c) => {
                out.push(CREDENTIAL);
                put_bytes(&mut out, &c.id.0);
                put_key(&mut out, &c.public_key);
                out.extend_from_slice(&c.sign_count.to_be_bytes());
                put_pick(
                    &mut out,
                    &[UserVerification::Verified, UserVerification::PresenceOnly],
                    &c.uv_initialized,
                );
                put_list(&mut out, &c.transports, |o, t| put_pick(o, &TRANSPORTS, t))?;
                out.push(match c.backup {
                    Backup::SingleDevice => 0,
                    Backup::MultiDevice(BackupState::NotBackedUp) => 1,
                    Backup::MultiDevice(BackupState::BackedUp) => 2,
                });
                put_bytes(&mut out, &c.user.0);
                out.extend_from_slice(&c.aaguid.0);
                let a = &c.attestation;
                put_pick(&mut out, &FORMATS, &a.format);
                put_pick(&mut out, &KINDS, &a.kind);
                put_pick(&mut out, &TRUSTS, &a.trust);
                put_list(&mut out, &a.chain, |o, d| o.extend_from_slice(d.as_bytes()))?;
                put_opt(&mut out, a.anchor.as_ref(), |o, d| {
                    o.extend_from_slice(d.as_bytes())
                });
            }
        }
        Ok(out)
    }
}

struct In<'a>(&'a [u8]);

impl<'a> In<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let (head, rest) = self.0.split_at_checked(n).ok_or_else(corrupt)?;
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        <[u8; N]>::try_from(self.take(N)?).map_err(|_| corrupt())
    }

    fn u8(&mut self) -> Result<u8, Error> {
        self.array::<1>().map(|[b]| b)
    }

    fn u32(&mut self) -> Result<u32, Error> {
        self.array().map(u32::from_be_bytes)
    }

    fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let n = usize::try_from(self.u32()?).map_err(|_| corrupt())?;
        self.take(n)
    }

    fn digest(&mut self) -> Result<Digest, Error> {
        self.array().map(Digest::from_bytes)
    }

    fn pick<T: Copy>(&mut self, table: &[T]) -> Result<T, Error> {
        table
            .get(usize::from(self.u8()?))
            .copied()
            .ok_or_else(corrupt)
    }

    fn opt<T>(
        &mut self,
        get: impl FnOnce(&mut Self) -> Result<T, Error>,
    ) -> Result<Option<T>, Error> {
        match self.u8()? {
            0 => Ok(None),
            1 => get(self).map(Some),
            _ => Err(corrupt()),
        }
    }

    fn list<T>(&mut self, get: impl Fn(&mut Self) -> Result<T, Error>) -> Result<Vec<T>, Error> {
        (0..self.u8()?).map(|_| get(self)).collect()
    }

    fn text(&mut self) -> Result<String, Error> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| corrupt())
    }

    fn user(&mut self) -> Result<UserHandle, Error> {
        UserHandle::from_stored(self.bytes()?).map_err(|_| corrupt())
    }

    fn eval(&mut self) -> Result<PrfEval, Error> {
        Ok(PrfEval {
            first: self.bytes()?.to_vec(),
            second: self.opt(|i| i.bytes().map(<[u8]>::to_vec))?,
        })
    }

    fn timeout(&mut self) -> Result<Timeout, Error> {
        Timeout::from_secs(self.u32()?).map_err(|_| corrupt())
    }

    fn key(&mut self) -> Result<CoseKey, Error> {
        Ok(match self.pick(&ALGORITHMS)? {
            CoseAlgorithm::Es256 => CoseKey::Es256 {
                x: self.array()?,
                y: self.array()?,
            },
            CoseAlgorithm::Es384 => CoseKey::Es384 {
                x: self.array()?,
                y: self.array()?,
            },
            CoseAlgorithm::EdDsa => CoseKey::EdDsa(self.array()?),
            CoseAlgorithm::Rs256 => CoseKey::Rs256 {
                n: self.bytes()?.to_vec(),
                e: self.bytes()?.to_vec(),
            },
        })
    }

    fn registration_options(&mut self) -> Result<RegistrationOptions, Error> {
        Ok(RegistrationOptions {
            user_verification: self.pick(&REQUIREMENTS)?,
            resident_key: self.pick(&RESIDENT_KEYS)?,
            timeout: self.timeout()?,
            algorithms: self.list(|i| i.pick(&ALGORITHMS))?,
            attachment: self.opt(|i| i.pick(&ATTACHMENTS))?,
            conveyance: self.pick(&CONVEYANCES)?,
            formats: self.list(|i| i.pick(&FORMATS))?,
            hints: self.list(|i| i.pick(&HINTS))?,
            mediation: self.pick(&MEDIATIONS)?,
            extensions: RegistrationExtensions {
                cred_props: match self.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(corrupt()),
                },
                prf: self.opt(|i| match i.u8()? {
                    0 => Ok(PrfRequest::Enable),
                    1 => i.eval().map(PrfRequest::Eval),
                    _ => Err(corrupt()),
                })?,
                large_blob: self.opt(|i| i.pick(&LARGE_BLOBS))?,
                app_id_exclude: self.opt(|i| i.text().map(AppId))?,
            },
        })
    }

    fn authentication_options(&mut self) -> Result<AuthenticationOptions, Error> {
        Ok(AuthenticationOptions {
            user_verification: self.pick(&REQUIREMENTS)?,
            timeout: self.timeout()?,
            hints: self.list(|i| i.pick(&HINTS))?,
            extensions: AuthenticationExtensions {
                app_id: self.opt(|i| i.text().map(AppId))?,
                prf: self.opt(Self::eval)?,
                prf_by_credential: self.list(|i| {
                    let id = CredentialId::from_bytes(i.bytes()?).map_err(|_| corrupt())?;
                    Ok((id, i.eval()?))
                })?,
                large_blob: self.opt(|i| match i.u8()? {
                    0 => Ok(LargeBlobOp::Read),
                    1 => i.bytes().map(|b| LargeBlobOp::Write(b.to_vec())),
                    _ => Err(corrupt()),
                })?,
            },
        })
    }

    fn credential(&mut self) -> Result<Credential, Error> {
        Ok(Credential {
            id: CredentialId::from_bytes(self.bytes()?).map_err(|_| corrupt())?,
            public_key: self.key()?,
            sign_count: self.u32()?,
            uv_initialized: self
                .pick(&[UserVerification::Verified, UserVerification::PresenceOnly])?,
            transports: self.list(|i| i.pick(&TRANSPORTS))?,
            backup: self.pick(&[
                Backup::SingleDevice,
                Backup::MultiDevice(BackupState::NotBackedUp),
                Backup::MultiDevice(BackupState::BackedUp),
            ])?,
            user: self.user()?,
            aaguid: Aaguid(self.array()?),
            attestation: Attestation {
                format: self.pick(&FORMATS)?,
                kind: self.pick(&KINDS)?,
                trust: self.pick(&TRUSTS)?,
                chain: self.list(Self::digest)?,
                anchor: self.opt(Self::digest)?,
            },
        })
    }
}

const fn corrupt() -> Error {
    Error::new(ErrorKind::Corrupt)
}

impl Record {
    /// Read a row back; an unknown version or shape is `Corrupt`, past `MAX_RECORD` is `TooLarge`.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_RECORD {
            return Err(Error::new(ErrorKind::TooLarge));
        }
        let mut i = In(bytes);
        if i.u8()? != VERSION {
            return Err(corrupt());
        }
        let record = match i.u8()? {
            REGISTRATION => Self::Registration(RegistrationCeremony {
                challenge: i.digest()?,
                browser: i.digest()?,
                deadline: UnixTime::new(u64::from_be_bytes(i.array()?)),
                user: i.user()?,
                options: i.registration_options()?,
            }),
            AUTHENTICATION => Self::Authentication(AuthenticationCeremony {
                challenge: i.digest()?,
                browser: i.digest()?,
                deadline: UnixTime::new(u64::from_be_bytes(i.array()?)),
                user: i.opt(In::user)?,
                allowed: i.list(In::digest)?,
                options: i.authentication_options()?,
            }),
            CREDENTIAL => Self::Credential(i.credential()?),
            _ => return Err(corrupt()),
        };
        if i.0.is_empty() {
            Ok(record)
        } else {
            Err(corrupt())
        }
    }
}

// a row the consumer's projection yields as this kind, at the version it was read
fn narrow<R, T>(
    row: &Row<R>,
    record: impl FnOnce(&R) -> Option<&Record>,
    pick: impl FnOnce(&Record) -> Option<&T>,
) -> Result<Row<T>, Error>
where
    T: Clone,
{
    let seen = record(row.record()).and_then(pick).ok_or_else(corrupt)?;
    Ok(Row::new(seen.clone(), row.version()))
}

impl RegistrationCeremony {
    /// Narrow a consumer's row to this ceremony, keeping its version; any other record is `Corrupt`.
    pub fn from_row<R>(
        row: &Row<R>,
        record: impl FnOnce(&R) -> Option<&Record>,
    ) -> Result<Row<Self>, Error> {
        narrow(row, record, |r| match r {
            Record::Registration(c) => Some(c),
            _ => None,
        })
    }
}

impl AuthenticationCeremony {
    /// Narrow a consumer's row to this ceremony, keeping its version; any other record is `Corrupt`.
    pub fn from_row<R>(
        row: &Row<R>,
        record: impl FnOnce(&R) -> Option<&Record>,
    ) -> Result<Row<Self>, Error> {
        narrow(row, record, |r| match r {
            Record::Authentication(c) => Some(c),
            _ => None,
        })
    }
}

impl Credential {
    /// Narrow a consumer's row to this credential, keeping its version; any other record is `Corrupt`.
    pub fn from_row<R>(
        row: &Row<R>,
        record: impl FnOnce(&R) -> Option<&Record>,
    ) -> Result<Row<Self>, Error> {
        narrow(row, record, |r| match r {
            Record::Credential(c) => Some(c),
            _ => None,
        })
    }

    /// The credential id.
    pub fn id(&self) -> &CredentialId {
        &self.id
    }

    /// The user the credential was registered for.
    pub fn user(&self) -> &UserHandle {
        &self.user
    }

    /// The id with its transports, for an allow or exclude list.
    pub fn descriptor(&self) -> CredentialDescriptor {
        CredentialDescriptor::new(self.id.clone(), &self.transports)
    }

    /// The credential public key's algorithm.
    pub fn algorithm(&self) -> CoseAlgorithm {
        self.public_key.algorithm()
    }

    /// The last accepted signature counter.
    pub fn sign_count(&self) -> u32 {
        self.sign_count
    }

    /// Backup eligibility and the last seen backup state.
    pub fn backup(&self) -> Backup {
        self.backup
    }

    /// `uvInitialized`: set by a user-verified registration or by `RelyingParty::confirm_user_verification`.
    pub fn uv_initialized(&self) -> UserVerification {
        self.uv_initialized
    }

    /// The transports the client reported at registration.
    pub fn transports(&self) -> &[Transport] {
        &self.transports
    }

    /// The AAGUID the authenticator reported: the model only when `attestation().trust()` is `Anchored`, else self-asserted.
    pub fn aaguid(&self) -> Aaguid {
        self.aaguid
    }

    /// How the registration was attested.
    pub fn attestation(&self) -> &Attestation {
        &self.attestation
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use base::{BrowserBinding, Digest, Row, Scope, Secret, StoreKey, UnixTime, Version};
    use sha2::{Digest as _, Sha256};

    use super::{
        Aaguid, AuthenticationCeremony, Credential, CredentialId, Key, Record,
        RegistrationCeremony, browser_digest,
    };
    use crate::cose::{CoseAlgorithm, CoseKey};
    use crate::error::{Error, ErrorKind};
    use crate::extensions::{
        AppId, LargeBlobOp, LargeBlobRequest, PrfEval, PrfRequest, RegistrationExtensions,
    };
    use crate::options::{
        Attachment, AuthenticationOptions, Conveyance, Hint, Mediation, RegistrationOptions,
        Requirement, ResidentKey, Timeout, Transport, UserHandle,
    };
    use crate::trust::{Attestation, AttestationType, Format, Trust};
    use crate::verify::{Backup, BackupState, UserVerification};
    use crate::{MAX_CREDENTIAL_ID, MAX_RECORD};

    fn bad<T>(_: T) -> Error {
        Error::new(ErrorKind::Corrupt)
    }

    fn digest(n: u8) -> Digest {
        Digest::from_bytes([n; 32])
    }

    fn user() -> Result<UserHandle, Error> {
        UserHandle::from_stored(b"user")
    }

    fn registration() -> Result<Record, Error> {
        let options = RegistrationOptions {
            user_verification: Requirement::Required,
            resident_key: ResidentKey::Preferred,
            timeout: Timeout::from_secs(90)?,
            algorithms: vec![CoseAlgorithm::EdDsa, CoseAlgorithm::Es256],
            attachment: Some(Attachment::CrossPlatform),
            conveyance: Conveyance::Enterprise,
            formats: vec![Format::Tpm, Format::Apple],
            hints: vec![Hint::Hybrid, Hint::SecurityKey],
            mediation: Mediation::Conditional,
            extensions: RegistrationExtensions {
                cred_props: true,
                prf: Some(PrfRequest::Eval(PrfEval {
                    first: vec![1, 2],
                    second: Some(vec![3]),
                })),
                large_blob: Some(LargeBlobRequest::Required),
                app_id_exclude: Some(AppId("https://a.example/app".into())),
            },
        };
        Ok(Record::Registration(RegistrationCeremony {
            challenge: digest(1),
            browser: digest(2),
            deadline: UnixTime::new(u64::MAX - 3),
            user: user()?,
            options,
        }))
    }

    fn authentication() -> Result<Record, Error> {
        let mut options =
            AuthenticationOptions::new(Requirement::Discouraged, Timeout::from_secs(600)?);
        options.hints = vec![Hint::ClientDevice];
        options.extensions.app_id = Some(AppId("https://a.example".into()));
        options.extensions.prf = Some(PrfEval {
            first: vec![9],
            second: None,
        });
        options.extensions.prf_by_credential = vec![(
            CredentialId::from_bytes(b"c1")?,
            PrfEval {
                first: vec![4],
                second: Some(vec![5]),
            },
        )];
        options.extensions.large_blob = Some(LargeBlobOp::Write(vec![7; 3]));
        Ok(Record::Authentication(AuthenticationCeremony {
            challenge: digest(3),
            browser: digest(4),
            deadline: UnixTime::new(1_700_000_000),
            user: Some(user()?),
            allowed: vec![digest(5), digest(6)],
            options,
        }))
    }

    fn credential(public_key: CoseKey) -> Result<Record, Error> {
        Ok(Record::Credential(Credential {
            id: CredentialId::from_bytes(b"credential")?,
            public_key,
            sign_count: 0x0102_0304,
            uv_initialized: UserVerification::PresenceOnly,
            transports: vec![Transport::Usb, Transport::Internal],
            backup: Backup::MultiDevice(BackupState::BackedUp),
            user: user()?,
            aaguid: Aaguid::from_bytes([6; 16]),
            attestation: Attestation {
                format: Format::Packed,
                kind: AttestationType::AttCa,
                trust: Trust::Anchored,
                chain: vec![digest(7), digest(8)],
                anchor: Some(digest(9)),
            },
        }))
    }

    fn keys() -> Vec<CoseKey> {
        vec![
            CoseKey::Es256 {
                x: [1; 32],
                y: [2; 32],
            },
            CoseKey::Es384 {
                x: [3; 48],
                y: [4; 48],
            },
            CoseKey::EdDsa([5; 32]),
            CoseKey::Rs256 {
                n: vec![6; 256],
                e: vec![1, 0, 1],
            },
        ]
    }

    fn all() -> Result<Vec<Record>, Error> {
        let credentials = keys()
            .into_iter()
            .map(credential)
            .collect::<Result<Vec<_>, _>>()?;
        Ok([vec![registration()?, authentication()?], credentials].concat())
    }

    #[test]
    fn every_record_reads_back_equal() -> Result<(), Error> {
        for record in all()? {
            assert_eq!(Record::decode(&record.encode()?), Ok(record));
        }
        let mut plain = authentication()?;
        if let Record::Authentication(c) = &mut plain {
            c.user = None;
            c.allowed = vec![];
            c.options = AuthenticationOptions::new(Requirement::Preferred, Timeout::from_secs(1)?);
            c.options.extensions.large_blob = Some(LargeBlobOp::Read);
        }
        assert_eq!(Record::decode(&plain.encode()?), Ok(plain));
        let mut single = credential(CoseKey::EdDsa([5; 32]))?;
        if let Record::Credential(c) = &mut single {
            c.backup = Backup::MultiDevice(BackupState::NotBackedUp);
            c.attestation.anchor = None;
            c.uv_initialized = UserVerification::Verified;
        }
        assert_eq!(Record::decode(&single.encode()?), Ok(single.clone()));
        if let Record::Credential(c) = &mut single {
            c.backup = Backup::SingleDevice;
        }
        assert_eq!(Record::decode(&single.encode()?), Ok(single));
        let mut conditional = registration()?;
        if let Record::Registration(c) = &mut conditional {
            c.options.extensions.prf = Some(PrfRequest::Enable);
            c.options.extensions.large_blob = Some(LargeBlobRequest::Preferred);
            c.options.attachment = Some(Attachment::Platform);
            c.options.mediation = Mediation::Optional;
        }
        assert_eq!(Record::decode(&conditional.encode()?), Ok(conditional));
        Ok(())
    }

    #[test]
    fn a_damaged_row_is_corrupt() -> Result<(), Error> {
        for record in all()? {
            let bytes = record.encode()?;
            for len in 0..bytes.len() {
                assert_eq!(
                    Record::decode(bytes.get(..len).unwrap_or(&[]))
                        .err()
                        .map(|e| e.kind()),
                    Some(ErrorKind::Corrupt),
                    "{len} of {}",
                    bytes.len()
                );
            }
            assert_eq!(
                Record::decode(&[bytes.as_slice(), &[0]].concat())
                    .err()
                    .map(|e| e.kind()),
                Some(ErrorKind::Corrupt)
            );
            for at in 0..bytes.len() {
                let mut damaged = bytes.clone();
                if let Some(b) = damaged.get_mut(at) {
                    *b ^= 0xff;
                }
                assert_ne!(Record::decode(&damaged), Ok(record.clone()), "byte {at}");
            }
            assert_eq!(
                Record::decode(&[&[2][..], bytes.get(1..).unwrap_or(&[])].concat())
                    .err()
                    .map(|e| e.kind()),
                Some(ErrorKind::Corrupt),
                "version"
            );
            assert_eq!(
                Record::decode(&[&bytes[..1], &[3], bytes.get(2..).unwrap_or(&[])].concat())
                    .err()
                    .map(|e| e.kind()),
                Some(ErrorKind::Corrupt),
                "kind"
            );
        }
        let long = vec![1; MAX_RECORD + 1];
        assert_eq!(
            Record::decode(&long).err().map(|e| e.kind()),
            Some(ErrorKind::TooLarge)
        );
        assert_eq!(
            Record::decode(&long[..MAX_RECORD]).err().map(|e| e.kind()),
            Some(ErrorKind::Corrupt)
        );
        Ok(())
    }

    #[test]
    fn keys_are_global() -> Result<(), Error> {
        assert_eq!(Key::Ceremony(digest(1)).scope(), Scope::Global);
        assert_eq!(
            Key::Credential(CredentialId::from_bytes(b"c")?).scope(),
            Scope::Global
        );
        Ok(())
    }

    #[test]
    fn ids_and_aaguids_are_bounded() -> Result<(), Error> {
        assert_eq!(
            CredentialId::from_bytes(&[]).err().map(|e| e.kind()),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            CredentialId::from_bytes(&[1]).map(|i| i.as_bytes().to_vec()),
            Ok(vec![1])
        );
        assert!(CredentialId::from_bytes(&[0; MAX_CREDENTIAL_ID]).is_ok());
        assert_eq!(
            CredentialId::from_bytes(&[0; MAX_CREDENTIAL_ID + 1])
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::TooLarge)
        );
        assert_eq!(Aaguid::from_bytes([4; 16]).as_bytes(), &[4; 16]);
        Ok(())
    }

    #[test]
    fn a_binding_keeps_its_labelled_digest() -> Result<(), Error> {
        let secret = [5; 32];
        let want = Sha256::new()
            .chain_update(b"base browser binding v1")
            .chain_update(secret)
            .finalize();
        assert_eq!(
            browser_digest(&BrowserBinding::from(&Secret::new(secret))),
            Ok(Digest::from_bytes(want.into()))
        );
        assert_ne!(
            browser_digest(&BrowserBinding::from(&Secret::new([6; 32]))),
            browser_digest(&BrowserBinding::from(&Secret::new(secret)))
        );
        Ok(())
    }

    #[test]
    fn rows_narrow_to_their_kind_and_keep_their_version() -> Result<(), Error> {
        let row = |r: Record| Row::new(r, Version::new(7));
        let ceremony = row(registration()?);
        assert_eq!(
            RegistrationCeremony::from_row(&ceremony, |r| Some(r)).map(|r| r.version()),
            Ok(Version::new(7))
        );
        assert_eq!(
            AuthenticationCeremony::from_row(&row(authentication()?), |r| Some(r))
                .map(|r| r.version()),
            Ok(Version::new(7))
        );
        assert_eq!(
            Credential::from_row(&row(credential(keys().remove(0))?), |r| Some(r))
                .map(|r| r.version()),
            Ok(Version::new(7))
        );
        let wrapped = Row::new((1, credential(keys().remove(0))?), Version::new(3));
        assert!(Credential::from_row(&wrapped, |(_, r)| Some(r)).is_ok());
        assert_eq!(
            Credential::from_row(&wrapped, |_| None)
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::Corrupt)
        );
        assert_eq!(
            Credential::from_row(&ceremony, |r| Some(r))
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::Corrupt)
        );
        assert_eq!(
            RegistrationCeremony::from_row(&row(authentication()?), |r| Some(r))
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::Corrupt)
        );
        assert_eq!(
            AuthenticationCeremony::from_row(&ceremony, |r| Some(r))
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::Corrupt)
        );
        Ok(())
    }

    #[test]
    fn credential_fields_are_readable() -> Result<(), Error> {
        let Record::Credential(c) = credential(keys().remove(0))? else {
            return Err(bad(()));
        };
        assert_eq!(
            (c.id().as_bytes(), c.user().as_bytes(), c.sign_count()),
            (&b"credential"[..], &b"user"[..], 0x0102_0304)
        );
        assert_eq!(
            (c.algorithm(), c.backup(), c.uv_initialized()),
            (
                CoseAlgorithm::Es256,
                Backup::MultiDevice(BackupState::BackedUp),
                UserVerification::PresenceOnly
            )
        );
        assert_eq!(
            (c.transports(), c.aaguid(), c.attestation().format),
            (
                &[Transport::Usb, Transport::Internal][..],
                Aaguid::from_bytes([6; 16]),
                Format::Packed
            )
        );
        assert_eq!(
            (c.descriptor().id().as_bytes(), c.descriptor().transports()),
            (
                &b"credential"[..],
                &[Transport::Usb, Transport::Internal][..]
            )
        );
        Ok(())
    }

    fn registration_with(
        algorithms: Vec<CoseAlgorithm>,
        formats: Vec<Format>,
        hints: Vec<Hint>,
    ) -> Result<Record, Error> {
        let mut record = registration()?;
        if let Record::Registration(c) = &mut record {
            c.options.algorithms = algorithms;
            c.options.formats = formats;
            c.options.hints = hints;
        }
        Ok(record)
    }

    #[test]
    fn a_list_past_one_byte_is_too_large_not_a_different_row() -> Result<(), Error> {
        let too_large = |r: Record| r.encode().err().map(|e| e.kind());
        for (algorithms, formats, hints) in [
            (vec![CoseAlgorithm::Es256; 256], vec![], vec![]),
            (vec![], vec![Format::None; 261], vec![]),
            (vec![], vec![], vec![Hint::Hybrid; 256]),
        ] {
            assert_eq!(
                too_large(registration_with(algorithms, formats, hints)?),
                Some(ErrorKind::TooLarge)
            );
        }
        let longest = registration_with(
            vec![CoseAlgorithm::Es256; 255],
            vec![Format::None; 255],
            vec![Hint::Hybrid; 255],
        )?;
        assert_eq!(Record::decode(&longest.encode()?), Ok(longest));
        Ok(())
    }

    #[test]
    fn the_setters_dedupe_to_their_table() -> Result<(), Error> {
        let mut options = RegistrationOptions::new(
            Requirement::Required,
            ResidentKey::Preferred,
            Timeout::from_secs(90)?,
        );
        let mut request =
            AuthenticationOptions::new(Requirement::Required, Timeout::from_secs(90)?);
        for i in 0..300 {
            options = options
                .algorithm(super::ALGORITHMS[i % 4])
                .attestation_format(super::FORMATS[i % 6])
                .hint(super::HINTS[i % 3]);
            request = request.hint(super::HINTS[i % 3]);
        }
        assert_eq!(options.algorithms, super::ALGORITHMS);
        assert_eq!(options.formats, super::FORMATS);
        assert_eq!(options.hints, super::HINTS);
        assert_eq!(request.hints, super::HINTS);
        Ok(())
    }

    #[test]
    fn a_non_canonical_cred_props_byte_is_corrupt() -> Result<(), Error> {
        let (mut on, mut off) = (registration()?, registration()?);
        for (record, flag) in [(&mut on, true), (&mut off, false)] {
            if let Record::Registration(c) = record {
                c.options.extensions.cred_props = flag;
            }
        }
        let (on, off) = (on.encode()?, off.encode()?);
        let flag = on
            .iter()
            .zip(&off)
            .position(|(a, b)| a != b)
            .ok_or_else(|| bad(()))?;
        for byte in [0, 1] {
            let mut row = on.clone();
            row[flag] = byte;
            assert!(Record::decode(&row).is_ok());
        }
        let mut row = on.clone();
        row[flag] = 2;
        assert_eq!(
            Record::decode(&row).err().map(|e| e.kind()),
            Some(ErrorKind::Corrupt)
        );
        Ok(())
    }

    mod identity {
        use alloc::boxed::Box;
        use alloc::vec::Vec;

        use proptest::prelude::*;
        use proptest::test_runner::{RngSeed, TestError, TestRunner};

        use super::super::{
            ALGORITHMS, AuthenticationCeremony, FORMATS, HINTS, KINDS, TRANSPORTS, TRUSTS,
        };
        use super::super::{Aaguid, Credential, CredentialId, Record, RegistrationCeremony};
        use super::{digest, user};
        use crate::cose::CoseKey;
        use crate::error::ErrorKind;
        use crate::extensions::{AppId, LargeBlobOp, LargeBlobRequest, PrfEval, PrfRequest};
        use crate::options::UserHandle;
        use crate::options::{
            AuthenticationOptions, Mediation, RegistrationOptions, Requirement, ResidentKey,
            Timeout,
        };
        use crate::trust::Attestation;
        use crate::verify::{Backup, BackupState, UserVerification};
        use base::UnixTime;

        fn pick<T: Clone + core::fmt::Debug + 'static>(
            table: &'static [T],
            max: usize,
        ) -> impl Strategy<Value = Vec<T>> {
            prop::collection::vec(prop::sample::select(table), 0..max)
        }

        fn eval() -> impl Strategy<Value = PrfEval> {
            (
                prop::collection::vec(any::<u8>(), 0..8),
                prop::option::of(prop::collection::vec(any::<u8>(), 0..8)),
            )
                .prop_map(|(first, second)| PrfEval { first, second })
        }

        fn registration(handle: UserHandle) -> impl Strategy<Value = Record> {
            (
                (
                    pick(&ALGORITHMS, 300),
                    pick(&FORMATS, 300),
                    pick(&HINTS, 300),
                ),
                (
                    any::<bool>(),
                    prop::option::of(prop_oneof![
                        Just(PrfRequest::Enable),
                        eval().prop_map(PrfRequest::Eval)
                    ]),
                    prop::option::of(prop_oneof![
                        Just(LargeBlobRequest::Required),
                        Just(LargeBlobRequest::Preferred)
                    ]),
                    prop::option::of("[a-z]{0,8}"),
                    prop::bool::ANY,
                ),
            )
                .prop_map(
                    move |((algorithms, formats, hints), (cp, prf, lb, app, cond))| {
                        let mut options = RegistrationOptions::new(
                            Requirement::Required,
                            ResidentKey::Required,
                            Timeout::from_secs(30).unwrap_or(Timeout(30)),
                        );
                        options.algorithms = algorithms;
                        options.formats = formats;
                        options.hints = hints;
                        options.mediation = if cond {
                            Mediation::Conditional
                        } else {
                            Mediation::Optional
                        };
                        options.extensions.cred_props = cp;
                        options.extensions.prf = prf;
                        options.extensions.large_blob = lb;
                        options.extensions.app_id_exclude = app.map(AppId);
                        Record::Registration(RegistrationCeremony {
                            challenge: digest(1),
                            browser: digest(2),
                            deadline: UnixTime::new(7),
                            user: handle.clone(),
                            options,
                        })
                    },
                )
        }

        fn authentication() -> impl Strategy<Value = Record> {
            (
                pick(&HINTS, 300),
                prop::collection::vec(any::<u8>(), 0..300),
                prop::option::of(eval()),
                prop::option::of(prop_oneof![
                    Just(LargeBlobOp::Read),
                    prop::collection::vec(any::<u8>(), 0..4).prop_map(LargeBlobOp::Write)
                ]),
            )
                .prop_map(|(hints, allowed, prf, large_blob)| {
                    let mut options = AuthenticationOptions::new(
                        Requirement::Preferred,
                        Timeout::from_secs(30).unwrap_or(Timeout(30)),
                    );
                    options.hints = hints;
                    options.extensions.prf = prf;
                    options.extensions.large_blob = large_blob;
                    options.extensions.prf_by_credential = allowed
                        .iter()
                        .filter_map(|b| CredentialId::from_bytes(&[*b]).ok())
                        .map(|id| {
                            (
                                id,
                                PrfEval {
                                    first: Vec::new(),
                                    second: None,
                                },
                            )
                        })
                        .collect();
                    Record::Authentication(AuthenticationCeremony {
                        challenge: digest(3),
                        browser: digest(4),
                        deadline: UnixTime::new(9),
                        user: None,
                        allowed: allowed.iter().map(|b| digest(*b)).collect(),
                        options,
                    })
                })
        }

        fn credential(handle: UserHandle, id: CredentialId) -> impl Strategy<Value = Record> {
            (
                pick(&TRANSPORTS, 300),
                prop::collection::vec(any::<u8>(), 0..300),
                any::<u32>(),
                0..3_u8,
                (
                    prop::sample::select(&FORMATS[..]),
                    prop::sample::select(&KINDS[..]),
                    prop::sample::select(&TRUSTS[..]),
                ),
            )
                .prop_map(
                    move |(transports, chain, sign_count, backup, (format, kind, trust))| {
                        Record::Credential(Credential {
                            id: id.clone(),
                            public_key: CoseKey::EdDsa([8; 32]),
                            sign_count,
                            uv_initialized: UserVerification::Verified,
                            transports,
                            backup: match backup {
                                0 => Backup::SingleDevice,
                                1 => Backup::MultiDevice(BackupState::NotBackedUp),
                                _ => Backup::MultiDevice(BackupState::BackedUp),
                            },
                            user: handle.clone(),
                            aaguid: Aaguid::from_bytes([1; 16]),
                            attestation: Attestation {
                                format,
                                kind,
                                trust,
                                chain: chain.iter().map(|b| digest(*b)).collect(),
                                anchor: None,
                            },
                        })
                    },
                )
        }

        fn widest(record: &Record) -> usize {
            match record {
                Record::Registration(c) => c
                    .options
                    .algorithms
                    .len()
                    .max(c.options.formats.len())
                    .max(c.options.hints.len()),
                Record::Authentication(c) => c
                    .allowed
                    .len()
                    .max(c.options.hints.len())
                    .max(c.options.extensions.prf_by_credential.len()),
                Record::Credential(c) => c.transports.len().max(c.attestation.chain.len()),
            }
        }

        #[test]
        fn record_round_trip() -> Result<(), Box<TestError<Record>>> {
            let (Ok(handle), Ok(id)) = (user(), CredentialId::from_bytes(b"id")) else {
                return Ok(());
            };
            let config = ProptestConfig {
                cases: 512,
                rng_seed: RngSeed::Fixed(0x5eed_0002),
                failure_persistence: None,
                ..ProptestConfig::default()
            };
            let rows = prop_oneof![
                registration(handle.clone()),
                authentication(),
                credential(handle, id)
            ];
            TestRunner::new(config)
                .run(&rows, |record| {
                    match record.encode() {
                        // the start paths refuse a row past MAX_RECORD, so only smaller rows must read back
                        Ok(bytes) if bytes.len() <= crate::MAX_RECORD => {
                            prop_assert_eq!(Record::decode(&bytes), Ok(record));
                        }
                        Ok(_) => {}
                        Err(e) => {
                            prop_assert_eq!(e.kind(), ErrorKind::TooLarge);
                            prop_assert!(widest(&record) > 255);
                        }
                    }
                    Ok(())
                })
                .map_err(Box::new)
        }
    }
}
