//! Parsed responses: shape checked before a finish runs, nothing verified (R16, R17, R20).
use alloc::vec::Vec;
use core::fmt;

use base::Digest;
use sha2::{Digest as _, Sha256};

use crate::authdata::AuthData;
use crate::client_data::ClientData;
use crate::error::{Error, ErrorKind, SpecStep};
use crate::extensions::ClientOutputs;
use crate::options::{Transport, UserHandle};
use crate::record::{CredentialId, Key};
use crate::{MAX_AUTHENTICATOR_DATA, MAX_SIGNATURE};

/// A parsed `AuthenticatorAttestationResponse`: client data, CBOR, authenticator data and statement shape checked, nothing verified. `Debug` prints no input bytes.
#[expect(dead_code, reason = "read by finish_registration, webauthn-05")]
pub struct RegistrationResponse {
    pub(crate) client_data_json: Vec<u8>,
    pub(crate) client_data: ClientData,
    pub(crate) attestation_object: Vec<u8>,
    pub(crate) auth_data: AuthData,
    pub(crate) transports: Vec<Transport>,
    pub(crate) extensions: ClientOutputs,
}

/// A parsed `AuthenticatorAssertionResponse`. `Debug` prints no input bytes.
#[expect(dead_code, reason = "extensions is read by webauthn-14")]
pub struct AuthenticationResponse {
    pub(crate) raw_id: CredentialId,
    pub(crate) client_data_json: Vec<u8>,
    pub(crate) client_data: ClientData,
    pub(crate) authenticator_data: Vec<u8>,
    pub(crate) auth_data: AuthData,
    pub(crate) signature: Vec<u8>,
    pub(crate) user_handle: Option<UserHandle>,
    pub(crate) extensions: ClientOutputs,
}

/// The keys an authentication response names.
#[derive(Clone, Debug)]
pub struct Lookup {
    pub(crate) ceremony: Key,
    pub(crate) credential: Key,
    pub(crate) user: Option<UserHandle>,
}

/// The SHA-256 digest of `bytes`.
pub(crate) fn sha256(bytes: &[u8]) -> Digest {
    Digest::from_bytes(Sha256::digest(bytes).into())
}

impl AuthenticationResponse {
    /// Parse the raw parts; each is bounded, an empty user handle reads as absent, and client extension results arrive only through the `serde` shape.
    pub fn new(
        raw_id: &[u8],
        client_data_json: &[u8],
        authenticator_data: &[u8],
        signature: &[u8],
        user_handle: Option<&[u8]>,
    ) -> Result<Self, Error> {
        if signature.len() > MAX_SIGNATURE || authenticator_data.len() > MAX_AUTHENTICATOR_DATA {
            return Err(Error::new(ErrorKind::TooLarge));
        }
        let client_data = ClientData::parse(client_data_json)
            .map_err(|e| Error::at(e.kind(), SpecStep::Authentication(9)))?;
        let auth_data = AuthData::parse(authenticator_data)?;
        if auth_data.attested.is_some() {
            return Err(Error::new(ErrorKind::Malformed));
        }
        Ok(Self {
            raw_id: CredentialId::from_bytes(raw_id)?,
            client_data_json: client_data_json.to_vec(),
            client_data,
            authenticator_data: authenticator_data.to_vec(),
            auth_data,
            signature: signature.to_vec(),
            user_handle: user_handle
                .filter(|h| !h.is_empty())
                .map(UserHandle::from_stored)
                .transpose()?,
            extensions: ClientOutputs::default(),
        })
    }

    /// The rows the host loads before finishing; no I/O.
    pub fn locate(&self) -> Lookup {
        Lookup {
            ceremony: Key::Ceremony(sha256(&self.client_data.challenge)),
            credential: Key::Credential(self.raw_id.clone()),
            user: self.user_handle.clone(),
        }
    }
}

impl Lookup {
    /// The ceremony row: `Key::Ceremony` of the challenge's SHA-256.
    pub fn ceremony(&self) -> &Key {
        &self.ceremony
    }

    /// The credential row: `Key::Credential` of the raw id.
    pub fn credential(&self) -> &Key {
        &self.credential
    }

    /// The user handle the response carries, if any.
    pub fn user(&self) -> Option<&UserHandle> {
        self.user.as_ref()
    }
}

impl fmt::Debug for RegistrationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegistrationResponse")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for AuthenticationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticationResponse")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::{AuthenticationResponse, RegistrationResponse, sha256};
    use crate::authdata::AuthData;
    use crate::client_data::ClientData;
    use crate::error::{ErrorKind, SpecStep};
    use crate::extensions::ClientOutputs;
    use crate::record::{CredentialId, Key};
    use crate::{MAX_AUTHENTICATOR_DATA, MAX_SIGNATURE, MAX_USER_HANDLE};

    const CHALLENGE: &str = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk";

    fn json() -> Vec<u8> {
        format!(
            r#"{{"type":"webauthn.get","challenge":"{CHALLENGE}","origin":"https://example.org"}}"#
        )
        .into_bytes()
    }

    fn data(flags: u8) -> Vec<u8> {
        [&[3; 32][..], &[flags], &[0, 0, 0, 6]].concat()
    }

    fn kind<T>(r: Result<T, crate::error::Error>) -> Option<ErrorKind> {
        r.err().map(|e| e.kind())
    }

    #[test]
    fn parts_are_parsed_and_located() -> Result<(), crate::error::Error> {
        let r = AuthenticationResponse::new(b"id", &json(), &data(1), b"sig", Some(b"user"))?;
        assert_eq!(
            (
                r.raw_id.as_bytes(),
                r.signature.as_slice(),
                r.authenticator_data.len(),
                r.client_data_json.len()
            ),
            (&b"id"[..], &b"sig"[..], 37, json().len())
        );
        assert_eq!(
            r.user_handle.as_ref().map(|u| u.as_bytes()),
            Some(&b"user"[..])
        );
        let lookup = r.locate();
        assert_eq!(lookup.ceremony(), &Key::Ceremony(sha256(&[9; 32])));
        assert_eq!(
            lookup.credential(),
            &Key::Credential(CredentialId::from_bytes(b"id")?)
        );
        assert_eq!(lookup.user().map(|u| u.as_bytes()), Some(&b"user"[..]));
        assert!(
            AuthenticationResponse::new(b"id", &json(), &data(1), b"sig", None)?
                .locate()
                .user()
                .is_none()
        );
        assert!(
            AuthenticationResponse::new(b"id", &json(), &data(1), b"sig", Some(b""))?
                .user_handle
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn every_part_is_bounded() {
        let new = |id: &[u8], cd: &[u8], ad: &[u8], sig: &[u8], user: &[u8]| {
            AuthenticationResponse::new(id, cd, ad, sig, Some(user))
        };
        assert_eq!(
            kind(new(b"", &json(), &data(1), b"s", b"u")),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            kind(new(&[1; 1024], &json(), &data(1), b"s", b"u")),
            Some(ErrorKind::TooLarge)
        );
        assert!(new(&[1; 1023], &json(), &data(1), b"s", b"u").is_ok());
        assert!(new(b"i", &json(), &data(1), &[0; MAX_SIGNATURE], b"u").is_ok());
        assert_eq!(
            kind(new(b"i", &json(), &data(1), &[0; MAX_SIGNATURE + 1], b"u")),
            Some(ErrorKind::TooLarge)
        );
        let padded = [data(1), vec![0; MAX_AUTHENTICATOR_DATA]].concat();
        assert_eq!(
            kind(new(
                b"i",
                &json(),
                &padded[..MAX_AUTHENTICATOR_DATA + 1],
                b"s",
                b"u"
            )),
            Some(ErrorKind::TooLarge)
        );
        assert!(new(b"i", &json(), &data(1), b"s", &[1; MAX_USER_HANDLE]).is_ok());
        assert_eq!(
            kind(new(
                b"i",
                &json(),
                &data(1),
                b"s",
                &[1; MAX_USER_HANDLE + 1]
            )),
            Some(ErrorKind::TooLarge)
        );
    }

    #[test]
    fn client_data_failures_name_step_9_and_keep_their_kind() {
        let step = Some(SpecStep::Authentication(9));
        let broken =
            AuthenticationResponse::new(b"i", b"type=webauthn.get", &data(1), b"s", None).err();
        assert_eq!(
            broken.map(|e| (e.kind(), e.spec_step())),
            Some((ErrorKind::Malformed, step))
        );
        let huge =
            AuthenticationResponse::new(b"i", &vec![b' '; 16_385], &data(1), b"s", None).err();
        assert_eq!(
            huge.map(|e| (e.kind(), e.spec_step())),
            Some((ErrorKind::TooLarge, step))
        );
    }

    #[test]
    fn authenticator_data_must_be_an_assertion() {
        assert_eq!(
            kind(AuthenticationResponse::new(
                b"i",
                &json(),
                &data(0x41),
                b"s",
                None
            )),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            kind(AuthenticationResponse::new(
                b"i",
                &json(),
                &data(1)[..36],
                b"s",
                None
            )),
            Some(ErrorKind::Malformed)
        );
    }

    #[test]
    fn debug_prints_no_part() -> Result<(), crate::error::Error> {
        let r = AuthenticationResponse::new(
            b"marker-id",
            &json(),
            &data(1),
            b"marker-sig",
            Some(b"marker-user"),
        )?;
        let registration = RegistrationResponse {
            client_data_json: b"marker".to_vec(),
            client_data: ClientData::parse(&json())?,
            attestation_object: b"marker".to_vec(),
            auth_data: AuthData::parse(&data(1))?,
            transports: vec![],
            extensions: ClientOutputs::default(),
        };
        for shown in [format!("{r:?}"), format!("{registration:?}")] {
            assert!(
                !shown.contains("marker") && !shown.contains("example.org"),
                "{shown}"
            );
        }
        assert!(format!("{r:?}").starts_with("AuthenticationResponse"));
        assert!(format!("{registration:?}").starts_with("RegistrationResponse"));
        Ok(())
    }
}
