//! The ceremonies: start, finish and their verdicts (L3 7.1, 7.2); authentication with webauthn-04, registration with webauthn-05.
use base::{BrowserBinding, Effect as BaseEffect, Entropy, Row, UnixTime};

use crate::attestation::{Statement, verify as verify_statement};
use crate::authdata::{BE, BS, UP, UV};
use crate::client_data::ClientData;
use crate::cose::CoseAlgorithm;
use crate::error::{Error, ErrorKind, SpecStep};
use crate::extensions::{
    AppIdUsed, AuthenticationOutputs, Discoverability, LargeBlobOutcome, LargeBlobSupport,
    PrfResult, RegistrationOutputs,
};
use crate::options::{
    Allow, AuthenticationOptions, CreationOptions, CredentialDescriptor, Mediation,
    RegistrationOptions, RequestOptions, Requirement, UserEntity, UserHandle,
};
use crate::policy::{CounterPolicy, CrossOrigin, RelyingParty, TrustPolicy, UnsolicitedExtensions};
use crate::record::{
    AuthenticationCeremony, Credential, CredentialId, Key, Record, RegistrationCeremony,
    browser_digest,
};
use crate::response::{AuthenticationResponse, RegistrationResponse, sha256, split};
use crate::trust::{Attestation, Format, Trust, TrustSource};
use crate::{Effect, MAX_LISTED_CREDENTIALS, MAX_RECORD, Pending, Verdict};

/// A verified registration; made only by `finish_registration`.
#[derive(Debug)]
#[expect(
    dead_code,
    reason = "extensions is read by the accessors of webauthn-14"
)]
pub struct Registered {
    pub(crate) credential: Credential,
    pub(crate) user_verification: UserVerification,
    pub(crate) extensions: RegistrationOutputs,
}

/// A verified assertion; made only by `finish_authentication`.
#[derive(Debug)]
#[expect(
    dead_code,
    reason = "extensions is read by the accessors of webauthn-14"
)]
pub struct Assertion {
    pub(crate) credential_id: CredentialId,
    pub(crate) user: UserHandle,
    pub(crate) user_verification: AssertionVerification,
    pub(crate) backup: Backup,
    pub(crate) counter: Counter,
    pub(crate) extensions: AuthenticationOutputs,
}

/// The UV flag of a registration, and a credential's `uvInitialized`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserVerification {
    /// UV set.
    Verified,
    /// UP only.
    PresenceOnly,
}

/// The UV flag of an assertion, read against the credential's `uvInitialized` (L3 6.1 and 7.2 step 24).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssertionVerification {
    /// UV set, and `uvInitialized` true: an authentication factor.
    Verified,
    /// UV set, and `uvInitialized` false: not a factor until an extra one succeeds and `confirm_user_verification` commits.
    FirstUse,
    /// UV clear.
    PresenceOnly,
}

/// The BE and BS flags; BS without BE has no value here.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backup {
    /// BE clear: a single-device credential.
    SingleDevice,
    /// BE set: a multi-device credential, with BS.
    MultiDevice(BackupState),
}

/// The BS flag of a multi-device credential.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupState {
    /// BS set.
    BackedUp,
    /// BS clear.
    NotBackedUp,
}

/// What the signature counter did (L3 7.2 step 22).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Counter {
    /// Stored and seen are both zero.
    Unsupported,
    /// Seen is greater than stored.
    Advanced(u32),
    /// Seen is not greater than stored, under `CounterPolicy::Tolerate`.
    Regressed {
        /// The stored count, which the effect keeps.
        stored: u32,
        /// The count in the assertion.
        seen: u32,
    },
}

const fn refuse(kind: ErrorKind, step: u8) -> Error {
    Error::at(kind, SpecStep::Authentication(step))
}

const fn refuse_registration(kind: ErrorKind, step: u8) -> Error {
    Error::at(kind, SpecStep::Registration(step))
}

const DEFAULT_ALGORITHMS: [CoseAlgorithm; 4] = [
    CoseAlgorithm::Es256,
    CoseAlgorithm::EdDsa,
    CoseAlgorithm::Es384,
    CoseAlgorithm::Rs256,
];

// the same bytes, with no early exit
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |d, (x, y)| d | (x ^ y)) == 0
}

impl RelyingParty {
    /// L3 7.1 step 1, bound to the starting browser: options for the client, and the effect that creates the ceremony row under its challenge's digest, expiring at its deadline; an over-long list or salt is `TooLarge`.
    pub fn start_registration(
        &self,
        user: &UserEntity,
        exclude: &[CredentialDescriptor],
        opts: &RegistrationOptions,
        browser: &BrowserBinding,
        now: UnixTime,
        e: &mut impl Entropy,
    ) -> Result<(CreationOptions, Effect), Error> {
        if exclude.len() > MAX_LISTED_CREDENTIALS {
            return Err(Error::new(ErrorKind::TooLarge));
        }
        let mut challenge = [0; 32];
        e.fill(&mut challenge);
        let digest = sha256(&challenge);
        let deadline = now.saturating_add(u64::from(opts.timeout.secs()));
        let record = Record::Registration(RegistrationCeremony {
            challenge: digest,
            browser: browser_digest(browser)?,
            deadline,
            user: user.handle.clone(),
            options: opts.clone(),
        });
        if record.encode()?.len() > MAX_RECORD {
            return Err(Error::new(ErrorKind::TooLarge));
        }
        let creation = CreationOptions {
            challenge,
            rp_id: self.id.clone(),
            rp_name: self.name.clone(),
            user: user.clone(),
            exclude: exclude.to_vec(),
            options: opts.clone(),
        };
        Ok((
            creation,
            BaseEffect::created(e, Key::Ceremony(digest), record, Some(deadline)),
        ))
    }

    /// L3 7.1 steps 5-29, in the browser the ceremony started in. Every failure, expiry included, is inside the verdict; the effect always deletes the seen ceremony row, and on `Ok` also reserves the credential id.
    pub fn finish_registration(
        &self,
        state: Row<RegistrationCeremony>,
        response: &RegistrationResponse,
        browser: &BrowserBinding,
        trust: &dyn TrustSource,
        now: UnixTime,
        e: &mut impl Entropy,
    ) -> Verdict<Registered> {
        let ceremony = Key::Ceremony(state.record().challenge);
        let (registered, credential) =
            match self.verify_registration(state.record(), response, browser, trust, now) {
                Ok(done) => done,
                Err(err) => {
                    return Pending::new(Err(err), BaseEffect::deleted(e, ceremony, &state));
                }
            };
        let key = Key::Credential(credential.id.clone());
        let built = BaseEffect::builder(&mut *e)
            .delete(ceremony.clone(), &state)
            .create(key, Record::Credential(credential), None)
            .build();
        match built {
            Ok(effect) => Pending::new(Ok(registered), effect),
            Err(_) => Pending::new(
                Err(Error::new(ErrorKind::Corrupt)),
                BaseEffect::deleted(e, ceremony, &state),
            ),
        }
    }

    fn verify_registration(
        &self,
        ceremony: &RegistrationCeremony,
        response: &RegistrationResponse,
        browser: &BrowserBinding,
        _trust: &dyn TrustSource,
        now: UnixTime,
    ) -> Result<(Registered, Credential), Error> {
        if !same(
            browser_digest(browser)?.as_bytes(),
            ceremony.browser.as_bytes(),
        ) {
            return Err(Error::new(ErrorKind::BrowserMismatch));
        }
        if now >= ceremony.deadline {
            return Err(Error::new(ErrorKind::Expired));
        }
        let (data, auth) = (&response.client_data, &response.auth_data);
        if data.kind != "webauthn.create" {
            return Err(refuse_registration(ErrorKind::Type, 7));
        }
        if sha256(&data.challenge) != ceremony.challenge {
            return Err(refuse_registration(ErrorKind::ChallengeMismatch, 8));
        }
        self.check_origins(data, SpecStep::Registration, [9, 10, 11])?;
        let parts = split(&response.attestation_object)?;
        if sha256(self.id.as_str().as_bytes()).as_bytes() != &auth.rp_id_hash {
            return Err(refuse_registration(ErrorKind::RpIdHash, 14));
        }
        if auth.flags & UP == 0 && ceremony.options.mediation != Mediation::Conditional {
            return Err(refuse_registration(ErrorKind::UserNotPresent, 15));
        }
        let verified = auth.flags & UV != 0;
        if !verified && ceremony.options.user_verification == Requirement::Required {
            return Err(refuse_registration(ErrorKind::UserNotVerified, 16));
        }
        let eligible = auth.flags & BE != 0;
        if auth.flags & BS != 0 && !eligible {
            return Err(refuse_registration(
                ErrorKind::BackupStateWithoutEligibility,
                17,
            ));
        }
        let attested = auth
            .attested
            .as_ref()
            .ok_or(refuse_registration(ErrorKind::Malformed, 13))?;
        let offered: &[CoseAlgorithm] = if ceremony.options.algorithms.is_empty() {
            &DEFAULT_ALGORITHMS
        } else {
            &ceremony.options.algorithms
        };
        if !offered.contains(&attested.public_key.algorithm()) {
            return Err(refuse_registration(ErrorKind::Algorithm, 20));
        }
        let statement = Statement {
            att_stmt: &parts.att_stmt,
            auth_data: auth,
            auth_data_bytes: parts.auth_data_bytes,
            client_data_hash: *sha256(&response.client_data_json).as_bytes(),
        };
        let checked = verify_statement(parts.fmt, &statement).map_err(|e| {
            refuse_registration(
                e.kind(),
                if e.kind() == ErrorKind::AttestationInvalid {
                    22
                } else {
                    21
                },
            )
        })?;
        if self.trust == TrustPolicy::RequireTrusted {
            return Err(refuse_registration(ErrorKind::Untrusted, 24));
        }
        if auth.extensions.is_some() && self.unsolicited == UnsolicitedExtensions::Reject {
            return Err(refuse_registration(ErrorKind::Extension, 28));
        }
        let backup = match (eligible, auth.flags & BS != 0) {
            (false, _) => Backup::SingleDevice,
            (true, true) => Backup::MultiDevice(BackupState::BackedUp),
            (true, false) => Backup::MultiDevice(BackupState::NotBackedUp),
        };
        let user_verification = if verified {
            UserVerification::Verified
        } else {
            UserVerification::PresenceOnly
        };
        let credential = Credential {
            id: attested.id.clone(),
            public_key: attested.public_key.clone(),
            sign_count: auth.sign_count,
            uv_initialized: user_verification,
            transports: response.transports.clone(),
            backup,
            user: ceremony.user.clone(),
            aaguid: attested.aaguid,
            attestation: Attestation {
                format: Format::None,
                kind: checked.kind,
                trust: Trust::Unanchored,
                chain: checked.x5c.iter().map(|c| sha256(c)).collect(),
                anchor: None,
            },
        };
        let registered = Registered {
            credential: credential.clone(),
            user_verification,
            extensions: RegistrationOutputs {
                discoverability: Discoverability::NotRequested,
                prf: PrfResult::NotRequested,
                large_blob: LargeBlobSupport::NotRequested,
            },
        };
        Ok((registered, credential))
    }

    /// L3 7.2 step 1, bound to the starting browser: options for the client, and the effect that creates the ceremony row.
    pub fn start_authentication(
        &self,
        allow: Allow<'_>,
        opts: &AuthenticationOptions,
        browser: &BrowserBinding,
        now: UnixTime,
        e: &mut impl Entropy,
    ) -> Result<(RequestOptions, Effect), Error> {
        let (user, listed) = match allow {
            Allow::User { user, credentials } => (Some(user.clone()), credentials),
            Allow::Discoverable => (None, &[][..]),
        };
        if listed.len() > MAX_LISTED_CREDENTIALS {
            return Err(Error::new(ErrorKind::TooLarge));
        }
        let mut challenge = [0; 32];
        e.fill(&mut challenge);
        let digest = sha256(&challenge);
        let deadline = now.saturating_add(u64::from(opts.timeout.secs()));
        let record = Record::Authentication(AuthenticationCeremony {
            challenge: digest,
            browser: browser_digest(browser)?,
            deadline,
            user,
            allowed: listed.iter().map(|d| sha256(d.id.as_bytes())).collect(),
            options: opts.clone(),
        });
        if record.encode()?.len() > MAX_RECORD {
            return Err(Error::new(ErrorKind::TooLarge));
        }
        let request = RequestOptions {
            challenge,
            rp_id: self.id.clone(),
            allow: listed.to_vec(),
            options: opts.clone(),
        };
        Ok((
            request,
            BaseEffect::created(e, Key::Ceremony(digest), record, Some(deadline)),
        ))
    }

    /// L3 7.2 steps 5-24, in the browser the ceremony started in. Every failure is inside the verdict; the effect always deletes the seen ceremony row, and on `Ok` also updates the seen credential row.
    pub fn finish_authentication(
        &self,
        state: Row<AuthenticationCeremony>,
        stored: Row<Credential>,
        response: &AuthenticationResponse,
        browser: &BrowserBinding,
        now: UnixTime,
        e: &mut impl Entropy,
    ) -> Verdict<Assertion> {
        let ceremony = Key::Ceremony(state.record().challenge);
        let (assertion, credential) =
            match self.verify_assertion(state.record(), stored.record(), response, browser, now) {
                Ok(done) => done,
                Err(err) => {
                    return Pending::new(Err(err), BaseEffect::deleted(e, ceremony, &state));
                }
            };
        let key = Key::Credential(credential.id.clone());
        let built = BaseEffect::builder(&mut *e)
            .delete(ceremony.clone(), &state)
            .update(key, &stored, Record::Credential(credential), None)
            .build();
        match built {
            Ok(effect) => Pending::new(Ok(assertion), effect),
            Err(_) => Pending::new(
                Err(Error::new(ErrorKind::Corrupt)),
                BaseEffect::deleted(e, ceremony, &state),
            ),
        }
    }

    fn verify_assertion(
        &self,
        ceremony: &AuthenticationCeremony,
        stored: &Credential,
        response: &AuthenticationResponse,
        browser: &BrowserBinding,
        now: UnixTime,
    ) -> Result<(Assertion, Credential), Error> {
        if !same(
            browser_digest(browser)?.as_bytes(),
            ceremony.browser.as_bytes(),
        ) {
            return Err(Error::new(ErrorKind::BrowserMismatch));
        }
        if now >= ceremony.deadline {
            return Err(Error::new(ErrorKind::Expired));
        }
        let (data, auth) = (&response.client_data, &response.auth_data);
        if !ceremony.allowed.is_empty()
            && !ceremony
                .allowed
                .contains(&sha256(response.raw_id.as_bytes()))
        {
            return Err(refuse(ErrorKind::NotAllowed, 5));
        }
        let handle = response.user_handle.as_ref();
        let user_ok = match &ceremony.user {
            Some(user) => stored.user == *user && handle.is_none_or(|h| h == user),
            None => handle == Some(&stored.user),
        };
        if stored.id != response.raw_id {
            return Err(refuse(ErrorKind::CredentialMismatch, 6));
        }
        if !user_ok {
            return Err(refuse(ErrorKind::UserHandleMismatch, 6));
        }
        if data.kind != "webauthn.get" {
            return Err(refuse(ErrorKind::Type, 10));
        }
        if sha256(&data.challenge) != ceremony.challenge {
            return Err(refuse(ErrorKind::ChallengeMismatch, 11));
        }
        self.check_origins(data, SpecStep::Authentication, [12, 13, 14])?;
        if sha256(self.id.as_str().as_bytes()).as_bytes() != &auth.rp_id_hash {
            return Err(refuse(ErrorKind::RpIdHash, 15));
        }
        if auth.flags & UP == 0 {
            return Err(refuse(ErrorKind::UserNotPresent, 16));
        }
        let verified = auth.flags & UV != 0;
        if !verified && ceremony.options.user_verification == Requirement::Required {
            return Err(refuse(ErrorKind::UserNotVerified, 17));
        }
        let eligible = auth.flags & BE != 0;
        if auth.flags & BS != 0 && !eligible {
            return Err(refuse(ErrorKind::BackupStateWithoutEligibility, 18));
        }
        if eligible != matches!(stored.backup, Backup::MultiDevice(_)) {
            return Err(refuse(ErrorKind::BackupEligibilityChanged, 19));
        }
        let signed = [
            response.authenticator_data.as_slice(),
            sha256(&response.client_data_json).as_bytes(),
        ]
        .concat();
        stored
            .public_key
            .verify(&signed, &response.signature)
            .map_err(|e| refuse(e.kind(), 21))?;
        let counter = match (stored.sign_count, auth.sign_count) {
            (0, 0) => Counter::Unsupported,
            (had, seen) if seen > had => Counter::Advanced(seen),
            (stored, seen) => match self.counter {
                CounterPolicy::Reject => return Err(refuse(ErrorKind::CounterRegressed, 22)),
                _ => Counter::Regressed { stored, seen },
            },
        };
        if auth.extensions.is_some() && self.unsolicited == UnsolicitedExtensions::Reject {
            return Err(refuse(ErrorKind::Extension, 23));
        }
        let backup = match (eligible, auth.flags & BS != 0) {
            (false, _) => Backup::SingleDevice,
            (true, true) => Backup::MultiDevice(BackupState::BackedUp),
            (true, false) => Backup::MultiDevice(BackupState::NotBackedUp),
        };
        let user_verification = match (verified, stored.uv_initialized) {
            (false, _) => AssertionVerification::PresenceOnly,
            (true, UserVerification::Verified) => AssertionVerification::Verified,
            (true, _) => AssertionVerification::FirstUse,
        };
        let credential = Credential {
            sign_count: if let Counter::Advanced(seen) = counter {
                seen
            } else {
                stored.sign_count
            },
            backup,
            ..stored.clone()
        };
        let assertion = Assertion {
            credential_id: stored.id.clone(),
            user: stored.user.clone(),
            user_verification,
            backup,
            counter,
            extensions: AuthenticationOutputs {
                app_id: AppIdUsed::NotUsed,
                prf: PrfResult::NotRequested,
                large_blob: LargeBlobOutcome::NotRequested,
            },
        };
        Ok((assertion, credential))
    }

    /// Raise the credential's `uvInitialized`, the step L3 7.2 step 24 says to skip unless an extra factor authorized it: an `update` of the seen row (O11).
    pub fn confirm_user_verification(
        &self,
        stored: &Row<Credential>,
        e: &mut impl Entropy,
    ) -> Effect {
        let raised = Credential {
            uv_initialized: UserVerification::Verified,
            ..stored.record().clone()
        };
        BaseEffect::updated(
            e,
            Key::Credential(raised.id.clone()),
            stored,
            Record::Credential(raised),
            None,
        )
    }

    // origin, cross-origin and top-origin steps (L3 7.1 steps 9-11, 7.2 steps 12-14)
    pub(crate) fn check_origins(
        &self,
        data: &ClientData,
        wrap: fn(u8) -> SpecStep,
        steps: [u8; 3],
    ) -> Result<(), Error> {
        let [origin, cross, top] = steps;
        if !self.origins.iter().any(|o| o.as_str() == data.origin) {
            return Err(Error::at(ErrorKind::OriginMismatch, wrap(origin)));
        }
        let listed = |t: &str| matches!(&self.cross_origin, CrossOrigin::Listed(l) if l.iter().any(|o| o.as_str() == t));
        match (
            data.cross_origin == Some(true),
            data.top_origin.as_deref(),
            &self.cross_origin,
        ) {
            (false, Some(_), _) | (true, None, CrossOrigin::Listed(_)) => {
                Err(Error::at(ErrorKind::TopOriginDenied, wrap(top)))
            }
            (true, _, CrossOrigin::Deny) => {
                Err(Error::at(ErrorKind::CrossOriginDenied, wrap(cross)))
            }
            (true, Some(t), CrossOrigin::Listed(_)) if !listed(t) => {
                Err(Error::at(ErrorKind::TopOriginDenied, wrap(top)))
            }
            _ => Ok(()),
        }
    }
}

impl Registered {
    /// The credential record the effect reserves.
    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    /// Whether the registration was user-verified; this becomes `uvInitialized`.
    pub fn user_verification(&self) -> UserVerification {
        self.user_verification
    }
}

impl Assertion {
    /// The credential that signed.
    pub fn credential_id(&self) -> &CredentialId {
        &self.credential_id
    }

    /// The credential's user.
    pub fn user(&self) -> &UserHandle {
        &self.user
    }

    /// The UV flag read against the credential's `uvInitialized`.
    pub fn user_verification(&self) -> AssertionVerification {
        self.user_verification
    }

    /// Backup eligibility and the current backup state.
    pub fn backup(&self) -> Backup {
        self.backup
    }

    /// What the signature counter did.
    pub fn counter(&self) -> Counter {
        self.counter
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    use base::{
        BrowserBinding, Digest, Effect as BaseEffect, Entropy, Secret, Slot, Store, UnixTime,
    };
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use store::MemStore;

    use super::{
        Assertion, AssertionVerification, Backup, BackupState, Counter, Registered,
        UserVerification, same,
    };
    use crate::cose::CoseKey;
    use crate::error::{Error, ErrorKind, SpecStep};
    use crate::extensions::{AppId, LargeBlobOp};
    use crate::options::{
        Allow, AuthenticationOptions, CredentialDescriptor, DisplayName, Mediation,
        RegistrationOptions, Requirement, ResidentKey, Timeout, Transport, UserEntity, UserHandle,
        UserName,
    };
    use crate::policy::{
        CounterPolicy, CrossOrigin, Origin, RelyingParty, RpId, TrustPolicy, UnsolicitedExtensions,
    };
    use crate::record::{
        Aaguid, AuthenticationCeremony, Credential, CredentialId, Key, Record,
        RegistrationCeremony, browser_digest,
    };
    use crate::response::{AuthenticationResponse, RegistrationResponse, sha256};
    use crate::testing::{attestation, auth_data, key};
    use crate::trust::{Attestation, AttestationType, Format, Trust, TrustSource};
    use crate::{MAX_LISTED_CREDENTIALS, MAX_RECORD};

    const NOW: u64 = 100;
    const DEADLINE: u64 = 160;
    const ID: &[u8] = b"id";
    const USER: &[u8] = b"user";

    fn bad<T>(_: T) -> Error {
        Error::new(ErrorKind::Corrupt)
    }

    // a valid assertion and the rows it finishes, each part open to a test's change
    struct Fx {
        key: SigningKey,
        rp: RelyingParty,
        ceremony: AuthenticationCeremony,
        stored: Credential,
        browser: BrowserBinding,
        now: u64,
        flags: u8,
        count: u32,
        rp_hash: Digest,
        kind: String,
        origin: String,
        cross: String,
        challenge: [u8; 32],
        raw_id: Vec<u8>,
        handle: Option<Vec<u8>>,
        extensions: bool,
    }

    struct Done {
        result: Result<Assertion, Error>,
        left: BTreeMap<Key, Record>,
        before: BTreeMap<Key, Record>,
    }

    impl Fx {
        fn new() -> Result<Self, Error> {
            let key = SigningKey::from_slice(&[7; 32]).map_err(bad)?;
            let point = key.verifying_key().to_sec1_point(false);
            let (x, y) = (point.x().ok_or(bad(()))?, point.y().ok_or(bad(()))?);
            let public_key = CoseKey::Es256 {
                x: x.as_slice().try_into().map_err(bad)?,
                y: y.as_slice().try_into().map_err(bad)?,
            };
            let rp = RelyingParty::builder(
                RpId::parse("example.org")?,
                DisplayName::parse("Example")?,
                Origin::parse("https://example.org")?,
                CounterPolicy::Reject,
            )
            .build()?;
            let browser = BrowserBinding::from(&Secret::new([5; 32]));
            let challenge = [9; 32];
            let user = UserHandle::from_stored(USER)?;
            let ceremony = AuthenticationCeremony {
                challenge: sha256(&challenge),
                browser: browser_digest(&browser)?,
                deadline: UnixTime::new(DEADLINE),
                user: Some(user.clone()),
                allowed: vec![],
                options: AuthenticationOptions::new(
                    Requirement::Preferred,
                    Timeout::from_secs(60)?,
                ),
            };
            let stored = Credential {
                id: CredentialId::from_bytes(ID)?,
                public_key,
                sign_count: 5,
                uv_initialized: UserVerification::Verified,
                transports: vec![],
                backup: Backup::SingleDevice,
                user,
                aaguid: Aaguid::from_bytes([0; 16]),
                attestation: Attestation {
                    format: Format::None,
                    kind: AttestationType::None,
                    trust: Trust::Unanchored,
                    chain: vec![],
                    anchor: None,
                },
            };
            Ok(Self {
                key,
                rp,
                ceremony,
                stored,
                browser,
                now: NOW,
                flags: 0x01,
                count: 6,
                rp_hash: sha256(b"example.org"),
                kind: "webauthn.get".into(),
                origin: "https://example.org".into(),
                cross: String::new(),
                challenge,
                raw_id: ID.to_vec(),
                handle: Some(USER.to_vec()),
                extensions: false,
            })
        }

        fn response(&self) -> Result<AuthenticationResponse, Error> {
            let challenge = base::b64url_encode(&self.challenge);
            let json = format!(
                r#"{{"type":"{}","challenge":"{challenge}","origin":"{}"{}}}"#,
                self.kind, self.origin, self.cross
            );
            let mut data = [
                self.rp_hash.as_bytes().as_slice(),
                &[self.flags | if self.extensions { 0x80 } else { 0 }],
                &self.count.to_be_bytes(),
            ]
            .concat();
            if self.extensions {
                data.push(0xa0);
            }
            let signed = [data.as_slice(), sha256(json.as_bytes()).as_bytes()].concat();
            let signature: Signature = self.key.sign(&signed);
            AuthenticationResponse::new(
                &self.raw_id,
                json.as_bytes(),
                &data,
                signature.to_der().as_bytes(),
                self.handle.as_deref(),
            )
        }

        fn run(&self) -> Result<Done, Error> {
            let start = UnixTime::new(0);
            let mut store: MemStore<Key, Record> = MemStore::default();
            let ceremony = Key::Ceremony(self.ceremony.challenge);
            let credential = Key::Credential(self.stored.id.clone());
            let rows = [
                (&ceremony, Record::Authentication(self.ceremony.clone())),
                (&credential, Record::Credential(self.stored.clone())),
            ];
            for (seed, (key, record)) in (11..).zip(rows) {
                let seed =
                    BaseEffect::created(&mut testkit::seeded(seed), key.clone(), record, None);
                store.apply(&seed, start).map_err(bad)?.map_err(bad)?;
            }
            let before = store.contents(start);
            let rows = store
                .load(&[ceremony.clone(), credential.clone()], start)
                .map_err(bad)?;
            let (Some(Slot::Row(c)), Some(Slot::Row(s))) =
                (rows.get(&ceremony), rows.get(&credential))
            else {
                return Err(bad(()));
            };
            let state = AuthenticationCeremony::from_row(c, |r| Some(r))?;
            let stored = Credential::from_row(s, |r| Some(r))?;
            let verdict = self.rp.finish_authentication(
                state,
                stored,
                &self.response()?,
                &self.browser,
                UnixTime::new(self.now),
                &mut testkit::seeded(20),
            );
            let receipt = store
                .apply(verdict.effect(), start)
                .map_err(bad)?
                .map_err(bad)?;
            Ok(Done {
                result: verdict.settle(receipt).map_err(bad)?,
                left: store.contents(start),
                before,
            })
        }

        fn refused(&self) -> Result<(ErrorKind, Option<SpecStep>), Error> {
            let done = self.run()?;
            let err = done.result.err().ok_or(bad(()))?;
            assert_eq!(
                done.left.keys().collect::<Vec<_>>(),
                vec![&Key::Credential(self.stored.id.clone())],
                "a refusal deletes the ceremony alone"
            );
            assert_eq!(
                done.left.get(&Key::Credential(self.stored.id.clone())),
                done.before.get(&Key::Credential(self.stored.id.clone()))
            );
            Ok((err.kind(), err.spec_step()))
        }
    }

    fn step(n: u8) -> Option<SpecStep> {
        Some(SpecStep::Authentication(n))
    }

    #[test]
    fn a_valid_assertion_updates_the_credential_and_deletes_the_ceremony() -> Result<(), Error> {
        let done = Fx::new()?.run()?;
        let assertion = done.result?;
        assert_eq!(
            (
                assertion.credential_id().as_bytes(),
                assertion.user().as_bytes()
            ),
            (ID, USER)
        );
        assert_eq!(assertion.counter(), Counter::Advanced(6));
        assert_eq!(
            assertion.user_verification(),
            AssertionVerification::PresenceOnly
        );
        assert_eq!(assertion.backup(), Backup::SingleDevice);
        let key = Key::Credential(CredentialId::from_bytes(ID)?);
        assert_eq!(done.left.keys().collect::<Vec<_>>(), vec![&key]);
        let Some(Record::Credential(c)) = done.left.get(&key) else {
            return Err(bad(()));
        };
        assert_eq!(
            (c.sign_count(), c.uv_initialized(), c.backup()),
            (6, UserVerification::Verified, Backup::SingleDevice)
        );
        Ok(())
    }

    #[test]
    fn each_check_names_its_kind_and_step() -> Result<(), Error> {
        let case = |change: fn(&mut Fx) -> Result<(), Error>,
                    kind: ErrorKind,
                    at: Option<SpecStep>|
         -> Result<(), Error> {
            let mut fx = Fx::new()?;
            change(&mut fx)?;
            assert_eq!(fx.refused()?, (kind, at), "{kind:?}");
            Ok(())
        };
        case(
            |f| {
                f.browser = BrowserBinding::from(&Secret::new([6; 32]));
                Ok(())
            },
            ErrorKind::BrowserMismatch,
            None,
        )?;
        case(
            |f| {
                f.now = DEADLINE;
                Ok(())
            },
            ErrorKind::Expired,
            None,
        )?;
        case(
            |f| {
                f.ceremony.allowed = vec![sha256(b"other")];
                Ok(())
            },
            ErrorKind::NotAllowed,
            step(5),
        )?;
        case(
            |f| {
                f.stored.id = CredentialId::from_bytes(b"other")?;
                Ok(())
            },
            ErrorKind::CredentialMismatch,
            step(6),
        )?;
        case(
            |f| {
                f.stored.user = UserHandle::from_stored(b"other")?;
                Ok(())
            },
            ErrorKind::UserHandleMismatch,
            step(6),
        )?;
        case(
            |f| {
                f.handle = Some(b"other".to_vec());
                Ok(())
            },
            ErrorKind::UserHandleMismatch,
            step(6),
        )?;
        case(
            |f| {
                f.kind = "webauthn.create".into();
                Ok(())
            },
            ErrorKind::Type,
            step(10),
        )?;
        case(
            |f| {
                f.challenge = [8; 32];
                Ok(())
            },
            ErrorKind::ChallengeMismatch,
            step(11),
        )?;
        case(
            |f| {
                f.origin = "https://evil.example".into();
                Ok(())
            },
            ErrorKind::OriginMismatch,
            step(12),
        )?;
        case(
            |f| {
                f.cross = r#","crossOrigin":true"#.into();
                Ok(())
            },
            ErrorKind::CrossOriginDenied,
            step(13),
        )?;
        case(
            |f| {
                f.cross = r#","topOrigin":"https://a.example""#.into();
                Ok(())
            },
            ErrorKind::TopOriginDenied,
            step(14),
        )?;
        case(
            |f| {
                f.rp_hash = sha256(b"evil.example");
                Ok(())
            },
            ErrorKind::RpIdHash,
            step(15),
        )?;
        case(
            |f| {
                f.flags = 0;
                Ok(())
            },
            ErrorKind::UserNotPresent,
            step(16),
        )?;
        case(
            |f| {
                f.ceremony.options.user_verification = Requirement::Required;
                Ok(())
            },
            ErrorKind::UserNotVerified,
            step(17),
        )?;
        case(
            |f| {
                f.flags = 0x11;
                Ok(())
            },
            ErrorKind::BackupStateWithoutEligibility,
            step(18),
        )?;
        case(
            |f| {
                f.flags = 0x09;
                Ok(())
            },
            ErrorKind::BackupEligibilityChanged,
            step(19),
        )?;
        case(
            |f| {
                f.stored.backup = Backup::MultiDevice(BackupState::BackedUp);
                Ok(())
            },
            ErrorKind::BackupEligibilityChanged,
            step(19),
        )?;
        case(
            |f| {
                f.count = 5;
                Ok(())
            },
            ErrorKind::CounterRegressed,
            step(22),
        )?;
        case(
            |f| {
                f.stored.sign_count = 7;
                Ok(())
            },
            ErrorKind::CounterRegressed,
            step(22),
        )?;
        case(
            |f| {
                f.extensions = true;
                Ok(())
            },
            ErrorKind::Extension,
            step(23),
        )?;
        case(
            |f| {
                f.key = SigningKey::from_slice(&[8; 32]).map_err(bad)?;
                Ok(())
            },
            ErrorKind::Signature,
            step(21),
        )?;
        Ok(())
    }

    #[test]
    fn the_deadline_is_exclusive() -> Result<(), Error> {
        let mut fx = Fx::new()?;
        fx.now = DEADLINE - 1;
        assert!(fx.run()?.result.is_ok());
        Ok(())
    }

    #[test]
    fn a_wrong_browser_fails_before_anything_else_is_read() -> Result<(), Error> {
        let mut fx = Fx::new()?;
        fx.browser = BrowserBinding::from(&Secret::new([6; 32]));
        fx.kind = "webauthn.create".into();
        assert_eq!(fx.refused()?.0, ErrorKind::BrowserMismatch);
        Ok(())
    }

    #[test]
    fn users_are_matched_by_the_allow_mode() -> Result<(), Error> {
        let mut fx = Fx::new()?;
        fx.handle = None;
        assert!(
            fx.run()?.result.is_ok(),
            "a user handle is optional when the user is named"
        );
        fx.ceremony.user = None;
        assert_eq!(
            fx.refused()?,
            (ErrorKind::UserHandleMismatch, step(6)),
            "discoverable needs the handle"
        );
        fx.handle = Some(USER.to_vec());
        assert!(fx.run()?.result.is_ok());
        fx.handle = Some(b"other".to_vec());
        assert_eq!(fx.refused()?.0, ErrorKind::UserHandleMismatch);
        fx.handle = Some(USER.to_vec());
        fx.stored.user = UserHandle::from_stored(b"other")?;
        assert_eq!(fx.refused()?.0, ErrorKind::UserHandleMismatch);
        Ok(())
    }

    #[test]
    fn an_allow_list_admits_its_members() -> Result<(), Error> {
        let mut fx = Fx::new()?;
        fx.ceremony.allowed = vec![sha256(b"other"), sha256(ID)];
        assert!(fx.run()?.result.is_ok());
        Ok(())
    }

    #[test]
    fn cross_origin_follows_the_policy() -> Result<(), Error> {
        let mut fx = Fx::new()?;
        let top = Origin::parse("https://top.example")?;
        let listed = |tops: Vec<Origin>| CrossOrigin::Listed(tops);
        let cross = r#","crossOrigin":true"#;
        let with_top = r#","crossOrigin":true,"topOrigin":"https://top.example""#;
        for (policy, json, want) in [
            (CrossOrigin::AnyTop, cross, None),
            (CrossOrigin::AnyTop, with_top, None),
            (
                CrossOrigin::Deny,
                with_top,
                Some(ErrorKind::CrossOriginDenied),
            ),
            (listed(vec![top.clone()]), with_top, None),
            (
                listed(vec![top.clone()]),
                cross,
                Some(ErrorKind::TopOriginDenied),
            ),
            (
                listed(vec![Origin::parse("https://other.example")?, top.clone()]),
                with_top,
                None,
            ),
            (
                listed(vec![Origin::parse("https://other.example")?]),
                with_top,
                Some(ErrorKind::TopOriginDenied),
            ),
            (
                CrossOrigin::AnyTop,
                r#","crossOrigin":false,"topOrigin":"https://top.example""#,
                Some(ErrorKind::TopOriginDenied),
            ),
            (CrossOrigin::AnyTop, r#","crossOrigin":false"#, None),
        ] {
            fx.rp.cross_origin = policy;
            fx.cross = json.into();
            assert_eq!(fx.run()?.result.err().map(|e| e.kind()), want, "{json}");
        }
        let mut fx = Fx::new()?;
        fx.rp.origins.push(Origin::parse("https://second.example")?);
        fx.origin = "https://second.example".into();
        assert!(fx.run()?.result.is_ok(), "any configured origin matches");
        Ok(())
    }

    #[test]
    fn counters_follow_the_policy() -> Result<(), Error> {
        let mut fx = Fx::new()?;
        fx.stored.sign_count = 0;
        fx.count = 0;
        assert_eq!(fx.run()?.result?.counter(), Counter::Unsupported);
        fx.count = 1;
        assert_eq!(fx.run()?.result?.counter(), Counter::Advanced(1));
        fx.stored.sign_count = 5;
        fx.count = 5;
        fx.rp.counter = CounterPolicy::Tolerate;
        let done = fx.run()?;
        assert_eq!(
            done.result?.counter(),
            Counter::Regressed { stored: 5, seen: 5 }
        );
        let Some(Record::Credential(c)) = done.left.get(&Key::Credential(fx.stored.id.clone()))
        else {
            return Err(bad(()));
        };
        assert_eq!(c.sign_count(), 5, "a regressed count is not stored");
        fx.count = 0;
        assert_eq!(
            fx.run()?.result?.counter(),
            Counter::Regressed { stored: 5, seen: 0 }
        );
        Ok(())
    }

    #[test]
    fn user_verification_and_backup_are_reported() -> Result<(), Error> {
        let mut fx = Fx::new()?;
        fx.flags = 0x05;
        assert_eq!(
            fx.run()?.result?.user_verification(),
            AssertionVerification::Verified
        );
        fx.stored.uv_initialized = UserVerification::PresenceOnly;
        assert_eq!(
            fx.run()?.result?.user_verification(),
            AssertionVerification::FirstUse
        );
        fx.stored.backup = Backup::MultiDevice(BackupState::NotBackedUp);
        fx.flags = 0x1d;
        let done = fx.run()?;
        assert_eq!(
            done.result?.backup(),
            Backup::MultiDevice(BackupState::BackedUp)
        );
        let Some(Record::Credential(c)) = done.left.get(&Key::Credential(fx.stored.id.clone()))
        else {
            return Err(bad(()));
        };
        assert_eq!(
            (c.backup(), c.uv_initialized()),
            (
                Backup::MultiDevice(BackupState::BackedUp),
                UserVerification::PresenceOnly
            ),
            "finishing never raises uvInitialized"
        );
        fx.flags = 0x0d;
        assert_eq!(
            fx.run()?.result?.backup(),
            Backup::MultiDevice(BackupState::NotBackedUp)
        );
        fx.ceremony.options.user_verification = Requirement::Required;
        assert!(fx.run()?.result.is_ok());
        fx.rp.unsolicited = UnsolicitedExtensions::Ignore;
        fx.extensions = true;
        assert!(fx.run()?.result.is_ok());
        Ok(())
    }

    #[test]
    fn confirming_raises_uv_initialized_alone() -> Result<(), Error> {
        let mut fx = Fx::new()?;
        fx.stored.uv_initialized = UserVerification::PresenceOnly;
        let mut store: MemStore<Key, Record> = MemStore::default();
        let key = Key::Credential(fx.stored.id.clone());
        let seed = BaseEffect::created(
            &mut testkit::seeded(11),
            key.clone(),
            Record::Credential(fx.stored.clone()),
            None,
        );
        store
            .apply(&seed, UnixTime::new(0))
            .map_err(bad)?
            .map_err(bad)?;
        let rows = store
            .load(core::slice::from_ref(&key), UnixTime::new(0))
            .map_err(bad)?;
        let Some(Slot::Row(row)) = rows.get(&key) else {
            return Err(bad(()));
        };
        let row = Credential::from_row(row, |r| Some(r))?;
        let effect = fx
            .rp
            .confirm_user_verification(&row, &mut testkit::seeded(13));
        store
            .apply(&effect, UnixTime::new(0))
            .map_err(bad)?
            .map_err(bad)?;
        let want = Credential {
            uv_initialized: UserVerification::Verified,
            ..fx.stored.clone()
        };
        assert_eq!(
            store.contents(UnixTime::new(0)).get(&key),
            Some(&Record::Credential(want))
        );
        Ok(())
    }

    #[test]
    fn start_authentication_emits_the_row_and_the_options() -> Result<(), Error> {
        let fx = Fx::new()?;
        let user = UserHandle::from_stored(USER)?;
        let listed = [
            CredentialDescriptor::new(CredentialId::from_bytes(ID)?, &[]),
            CredentialDescriptor::new(CredentialId::from_bytes(b"two")?, &[]),
        ];
        let options = AuthenticationOptions::new(Requirement::Required, Timeout::from_secs(30)?);
        let (request, effect) = fx.rp.start_authentication(
            Allow::User {
                user: &user,
                credentials: &listed,
            },
            &options,
            &fx.browser,
            UnixTime::new(NOW),
            &mut testkit::seeded(5),
        )?;
        let puts: Vec<_> = effect.puts().collect();
        let [(key, Record::Authentication(c), Some(expiry))] = puts.as_slice() else {
            return Err(bad(()));
        };
        assert_eq!(**key, Key::Ceremony(sha256(&request.challenge)));
        assert_eq!(
            (*expiry, c.deadline),
            (UnixTime::new(NOW + 30), UnixTime::new(NOW + 30))
        );
        assert_eq!(c.challenge, sha256(&request.challenge));
        assert_eq!(c.browser, browser_digest(&fx.browser)?);
        assert_eq!((c.user.as_ref(), c.options.clone()), (Some(&user), options));
        assert_eq!(c.allowed, vec![sha256(ID), sha256(b"two")]);
        assert_eq!(request.allow, listed);
        assert_eq!(request.rp_id, *fx.rp.id());
        assert_eq!(effect.guards().count() + effect.deletes().count(), 1);
        let again = fx.rp.start_authentication(
            Allow::Discoverable,
            &AuthenticationOptions::new(Requirement::Required, Timeout::from_secs(30)?),
            &fx.browser,
            UnixTime::new(NOW),
            &mut testkit::seeded(5),
        )?;
        assert_eq!(
            again.0.challenge, request.challenge,
            "the challenge is the entropy's 32 bytes"
        );
        let puts: Vec<_> = again.1.puts().collect();
        let [(_, Record::Authentication(d), _)] = puts.as_slice() else {
            return Err(bad(()));
        };
        assert_eq!((d.user.clone(), d.allowed.clone()), (None, vec![]));
        Ok(())
    }

    #[test]
    fn start_authentication_is_bounded() -> Result<(), Error> {
        let fx = Fx::new()?;
        let user = UserHandle::from_stored(USER)?;
        let descriptor = CredentialDescriptor::new(CredentialId::from_bytes(ID)?, &[]);
        let options = AuthenticationOptions::new(Requirement::Preferred, Timeout::from_secs(30)?);
        let start = |n: usize, options: &AuthenticationOptions| {
            let listed = vec![descriptor.clone(); n];
            fx.rp
                .start_authentication(
                    Allow::User {
                        user: &user,
                        credentials: &listed,
                    },
                    options,
                    &fx.browser,
                    UnixTime::new(NOW),
                    &mut testkit::seeded(5),
                )
                .map(|_| ())
        };
        assert_eq!(start(MAX_LISTED_CREDENTIALS, &options), Ok(()));
        assert_eq!(
            start(MAX_LISTED_CREDENTIALS + 1, &options)
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::TooLarge)
        );
        let mut big = options.clone();
        big.extensions.large_blob = Some(LargeBlobOp::Write(vec![0; MAX_RECORD]));
        assert_eq!(
            start(0, &big).err().map(|e| e.kind()),
            Some(ErrorKind::TooLarge)
        );
        let blob = |n: usize| {
            let mut o = options.clone();
            o.extensions.large_blob = Some(LargeBlobOp::Write(vec![0; n]));
            o
        };
        let (_, effect) = fx.rp.start_authentication(
            Allow::User {
                user: &user,
                credentials: &[],
            },
            &blob(0),
            &fx.browser,
            UnixTime::new(NOW),
            &mut testkit::seeded(5),
        )?;
        let Some((_, empty, _)) = effect.puts().next() else {
            return Err(bad(()));
        };
        let room = MAX_RECORD - empty.encode()?.len();
        assert_eq!(start(0, &blob(room)), Ok(()), "a row of exactly MAX_RECORD");
        assert_eq!(
            start(0, &blob(room + 1)).err().map(|e| e.kind()),
            Some(ErrorKind::TooLarge)
        );
        Ok(())
    }

    #[test]
    fn same_compares_every_byte() {
        assert!(same(b"abc", b"abc"));
        assert!(same(b"", b""));
        for other in [&b"abd"[..], b"xbc", b"abcd", b"ab", b""] {
            assert!(!same(b"abc", other));
        }
        assert!(!same(&[0b01], &[0b10]));
        assert!(!same(&[1, 1], &[0, 0]), "differences do not cancel");
    }

    struct Reg {
        rp: RelyingParty,
        ceremony: RegistrationCeremony,
        browser: BrowserBinding,
        extensions: bool,
        now: u64,
        flags: u8,
        count: u32,
        rp_hash: Digest,
        kind: String,
        origin: String,
        cross: String,
        challenge: [u8; 32],
        fmt: String,
        stmt: Vec<u8>,
        transports: Vec<Transport>,
    }

    struct Registering {
        result: Result<Registered, Error>,
        left: BTreeMap<Key, Record>,
    }

    struct Unknown;

    impl TrustSource for Unknown {
        fn decide(&self, _: &crate::trust::TrustQuery<'_>) -> crate::trust::TrustDecision<'_> {
            crate::trust::TrustDecision::Unknown
        }
    }

    impl Reg {
        fn new() -> Result<Self, Error> {
            let browser = BrowserBinding::from(&Secret::new([5; 32]));
            let challenge = [9; 32];
            let options = RegistrationOptions::new(
                Requirement::Preferred,
                ResidentKey::Preferred,
                Timeout::from_secs(60)?,
            );
            Ok(Self {
                rp: Fx::new()?.rp,
                ceremony: RegistrationCeremony {
                    challenge: sha256(&challenge),
                    browser: browser_digest(&browser)?,
                    deadline: UnixTime::new(DEADLINE),
                    user: UserHandle::from_stored(USER)?,
                    options,
                },
                browser,
                extensions: false,
                now: NOW,
                flags: 0x41,
                count: 3,
                rp_hash: sha256(b"example.org"),
                kind: "webauthn.create".into(),
                origin: "https://example.org".into(),
                cross: String::new(),
                challenge,
                fmt: "none".into(),
                stmt: vec![0xa0],
                transports: vec![Transport::Usb, Transport::Usb, Transport::Nfc],
            })
        }

        fn response(&self) -> Result<RegistrationResponse, Error> {
            let json = format!(
                r#"{{"type":"{}","challenge":"{}","origin":"{}"{}}}"#,
                self.kind,
                base::b64url_encode(&self.challenge),
                self.origin,
                self.cross
            );
            let (_, cose, _) = key()?;
            let cose = [cose, if self.extensions { vec![0xa0] } else { vec![] }].concat();
            let data = auth_data(
                self.rp_hash.as_bytes(),
                self.flags | if self.extensions { 0x80 } else { 0 },
                self.count,
                ID,
                &cose,
            );
            RegistrationResponse::new(
                ID,
                json.as_bytes(),
                &attestation(&self.fmt, &self.stmt, &data),
                &self.transports,
            )
        }

        fn run(&self) -> Result<Registering, Error> {
            let start = UnixTime::new(0);
            let mut store: MemStore<Key, Record> = MemStore::default();
            let ceremony = Key::Ceremony(self.ceremony.challenge);
            let seed = BaseEffect::created(
                &mut testkit::seeded(11),
                ceremony.clone(),
                Record::Registration(self.ceremony.clone()),
                None,
            );
            store.apply(&seed, start).map_err(bad)?.map_err(bad)?;
            let rows = store
                .load(core::slice::from_ref(&ceremony), start)
                .map_err(bad)?;
            let Some(Slot::Row(row)) = rows.get(&ceremony) else {
                return Err(bad(()));
            };
            let state = RegistrationCeremony::from_row(row, |r| Some(r))?;
            let verdict = self.rp.finish_registration(
                state,
                &self.response()?,
                &self.browser,
                &Unknown,
                UnixTime::new(self.now),
                &mut testkit::seeded(20),
            );
            let receipt = store
                .apply(verdict.effect(), start)
                .map_err(bad)?
                .map_err(bad)?;
            Ok(Registering {
                result: verdict.settle(receipt).map_err(bad)?,
                left: store.contents(start),
            })
        }

        fn refused(&self) -> Result<(ErrorKind, Option<SpecStep>), Error> {
            if let Err(e) = self.response() {
                return Ok((e.kind(), e.spec_step()));
            }
            let done = self.run()?;
            let err = done.result.err().ok_or(bad(()))?;
            assert!(
                done.left.is_empty(),
                "a refusal deletes the ceremony and registers nothing"
            );
            Ok((err.kind(), err.spec_step()))
        }
    }

    fn at(n: u8) -> Option<SpecStep> {
        Some(SpecStep::Registration(n))
    }

    #[test]
    fn a_valid_registration_reserves_the_credential_and_deletes_the_ceremony() -> Result<(), Error>
    {
        let done = Reg::new()?.run()?;
        let registered = done.result?;
        assert_eq!(
            registered.user_verification(),
            UserVerification::PresenceOnly
        );
        let c = registered.credential();
        assert_eq!(
            (c.id().as_bytes(), c.user().as_bytes(), c.sign_count()),
            (ID, USER, 3)
        );
        assert_eq!(
            (c.uv_initialized(), c.backup(), c.aaguid(), c.transports()),
            (
                UserVerification::PresenceOnly,
                Backup::SingleDevice,
                Aaguid::from_bytes([8; 16]),
                &[Transport::Usb, Transport::Nfc][..]
            )
        );
        assert_eq!(
            (
                c.attestation().format(),
                c.attestation().kind(),
                c.attestation().trust()
            ),
            (Format::None, AttestationType::None, Trust::Unanchored)
        );
        assert_eq!(
            (c.attestation().chain(), c.attestation().anchor()),
            (&[][..], None)
        );
        assert_eq!(c.algorithm(), crate::cose::CoseAlgorithm::Es256);
        assert_eq!(
            done.left.keys().collect::<Vec<_>>(),
            vec![&Key::Credential(CredentialId::from_bytes(ID)?)]
        );
        assert_eq!(
            done.left.values().next(),
            Some(&Record::Credential(c.clone()))
        );
        Ok(())
    }

    #[test]
    fn each_registration_check_names_its_kind_and_step() -> Result<(), Error> {
        let case = |change: fn(&mut Reg) -> Result<(), Error>,
                    kind: ErrorKind,
                    step: Option<SpecStep>|
         -> Result<(), Error> {
            let mut fx = Reg::new()?;
            change(&mut fx)?;
            assert_eq!(fx.refused()?, (kind, step), "{kind:?}");
            Ok(())
        };
        case(
            |f| {
                f.browser = BrowserBinding::from(&Secret::new([6; 32]));
                Ok(())
            },
            ErrorKind::BrowserMismatch,
            None,
        )?;
        case(
            |f| {
                f.now = DEADLINE;
                Ok(())
            },
            ErrorKind::Expired,
            None,
        )?;
        case(
            |f| {
                f.kind = "webauthn.get".into();
                Ok(())
            },
            ErrorKind::Type,
            at(7),
        )?;
        case(
            |f| {
                f.challenge = [8; 32];
                Ok(())
            },
            ErrorKind::ChallengeMismatch,
            at(8),
        )?;
        case(
            |f| {
                f.origin = "https://evil.example".into();
                Ok(())
            },
            ErrorKind::OriginMismatch,
            at(9),
        )?;
        case(
            |f| {
                f.cross = r#","crossOrigin":true"#.into();
                Ok(())
            },
            ErrorKind::CrossOriginDenied,
            at(10),
        )?;
        case(
            |f| {
                f.cross = r#","topOrigin":"https://a.example""#.into();
                Ok(())
            },
            ErrorKind::TopOriginDenied,
            at(11),
        )?;
        case(
            |f| {
                f.rp_hash = sha256(b"evil.example");
                Ok(())
            },
            ErrorKind::RpIdHash,
            at(14),
        )?;
        case(
            |f| {
                f.flags = 0x40;
                Ok(())
            },
            ErrorKind::UserNotPresent,
            at(15),
        )?;
        case(
            |f| {
                f.ceremony.options.user_verification = Requirement::Required;
                Ok(())
            },
            ErrorKind::UserNotVerified,
            at(16),
        )?;
        case(
            |f| {
                f.flags = 0x51;
                Ok(())
            },
            ErrorKind::BackupStateWithoutEligibility,
            at(17),
        )?;
        case(
            |f| {
                f.ceremony.options = f
                    .ceremony
                    .options
                    .clone()
                    .algorithm(crate::cose::CoseAlgorithm::Rs256);
                Ok(())
            },
            ErrorKind::Algorithm,
            at(20),
        )?;
        case(
            |f| {
                f.fmt = "None".into();
                Ok(())
            },
            ErrorKind::UnknownFormat,
            at(21),
        )?;
        case(
            |f| {
                f.fmt = "packed".into();
                Ok(())
            },
            ErrorKind::UnknownFormat,
            at(21),
        )?;
        case(
            |f| {
                f.stmt = vec![0xa1, 0x01, 0x02];
                Ok(())
            },
            ErrorKind::AttestationInvalid,
            at(22),
        )?;
        case(
            |f| {
                f.stmt = vec![0x80];
                Ok(())
            },
            ErrorKind::Malformed,
            at(13),
        )?;
        case(
            |f| {
                f.rp.trust = TrustPolicy::RequireTrusted;
                Ok(())
            },
            ErrorKind::Untrusted,
            at(24),
        )?;
        Ok(())
    }

    #[test]
    fn registration_options_choose_flags_and_algorithms() -> Result<(), Error> {
        let mut fx = Reg::new()?;
        fx.flags = 0x40;
        fx.ceremony.options = fx
            .ceremony
            .options
            .clone()
            .mediation(Mediation::Conditional);
        assert!(
            fx.run()?.result.is_ok(),
            "a conditional registration needs no UP"
        );
        let mut fx = Reg::new()?;
        fx.flags = 0x45;
        fx.ceremony.options.user_verification = Requirement::Required;
        let done = fx.run()?;
        assert_eq!(done.result?.user_verification(), UserVerification::Verified);
        let mut fx = Reg::new()?;
        fx.flags = 0x59;
        let done = fx.run()?;
        assert_eq!(
            done.result?.credential().backup(),
            Backup::MultiDevice(BackupState::BackedUp)
        );
        fx.flags = 0x49;
        assert_eq!(
            fx.run()?.result?.credential().backup(),
            Backup::MultiDevice(BackupState::NotBackedUp)
        );
        let mut fx = Reg::new()?;
        fx.ceremony.options = fx
            .ceremony
            .options
            .clone()
            .algorithm(crate::cose::CoseAlgorithm::Rs256)
            .algorithm(crate::cose::CoseAlgorithm::Es256);
        assert!(fx.run()?.result.is_ok());
        let mut fx = Reg::new()?;
        fx.cross = r#","crossOrigin":true"#.into();
        fx.rp.cross_origin = CrossOrigin::AnyTop;
        assert!(fx.run()?.result.is_ok());
        Ok(())
    }

    #[test]
    fn unsolicited_extensions_follow_the_policy() -> Result<(), Error> {
        let mut fx = Reg::new()?;
        fx.extensions = true;
        assert_eq!(fx.refused()?, (ErrorKind::Extension, at(28)));
        fx.rp.unsolicited = UnsolicitedExtensions::Ignore;
        assert!(fx.run()?.result.is_ok());
        Ok(())
    }

    #[test]
    fn start_registration_emits_the_row_and_the_options() -> Result<(), Error> {
        let fx = Reg::new()?;
        let user = UserEntity::new(
            UserHandle::from_stored(USER)?,
            UserName::parse("ada")?,
            DisplayName::parse("Ada")?,
        );
        let excluded = [CredentialDescriptor::new(
            CredentialId::from_bytes(ID)?,
            &[Transport::Usb],
        )];
        let options = fx.ceremony.options.clone();
        let (creation, effect) = fx.rp.start_registration(
            &user,
            &excluded,
            &options,
            &fx.browser,
            UnixTime::new(NOW),
            &mut testkit::seeded(5),
        )?;
        let puts: Vec<_> = effect.puts().collect();
        let [(key, Record::Registration(c), Some(expiry))] = puts.as_slice() else {
            return Err(bad(()));
        };
        assert_eq!(**key, Key::Ceremony(sha256(&creation.challenge)));
        assert_eq!(
            (*expiry, c.deadline, c.challenge),
            (
                UnixTime::new(NOW + 60),
                UnixTime::new(NOW + 60),
                sha256(&creation.challenge)
            )
        );
        assert_eq!(
            (c.browser, c.user.clone(), c.options.clone()),
            (
                browser_digest(&fx.browser)?,
                UserHandle::from_stored(USER)?,
                options
            )
        );
        assert_eq!(
            (
                creation.rp_id.as_str(),
                creation.exclude.clone(),
                creation.user == user
            ),
            ("example.org", excluded.to_vec(), true)
        );
        assert_eq!(creation.rp_name, DisplayName::parse("Example")?);
        let mut drawn = [0; 32];
        testkit::seeded(5).fill(&mut drawn);
        assert_eq!(creation.challenge, drawn);
        Ok(())
    }

    #[test]
    fn start_registration_is_bounded() -> Result<(), Error> {
        let fx = Reg::new()?;
        let user = UserEntity::new(
            UserHandle::from_stored(USER)?,
            UserName::parse("ada")?,
            DisplayName::parse("Ada")?,
        );
        let descriptor = CredentialDescriptor::new(CredentialId::from_bytes(ID)?, &[]);
        let start = |n: usize, options: &RegistrationOptions| {
            let listed = vec![descriptor.clone(); n];
            fx.rp
                .start_registration(
                    &user,
                    &listed,
                    options,
                    &fx.browser,
                    UnixTime::new(NOW),
                    &mut testkit::seeded(5),
                )
                .map(|(_, e)| e)
        };
        let options = fx.ceremony.options.clone();
        assert!(start(MAX_LISTED_CREDENTIALS, &options).is_ok());
        assert_eq!(
            start(MAX_LISTED_CREDENTIALS + 1, &options)
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::TooLarge)
        );
        let sized = |n: usize| {
            let mut o = options.clone();
            o.extensions.app_id_exclude = Some(AppId("a".repeat(n)));
            o
        };
        let effect = start(0, &sized(0))?;
        let Some((_, record, _)) = effect.puts().next() else {
            return Err(bad(()));
        };
        let room = MAX_RECORD - record.encode()?.len();
        assert!(
            start(0, &sized(room)).is_ok(),
            "a row of exactly MAX_RECORD"
        );
        assert_eq!(
            start(0, &sized(room + 1)).err().map(|e| e.kind()),
            Some(ErrorKind::TooLarge)
        );
        for lists in 0..3 {
            let mut o = options.clone();
            match lists {
                0 => o.hints = vec![crate::options::Hint::Hybrid; 256],
                1 => o.algorithms = vec![crate::cose::CoseAlgorithm::Es256; 256],
                _ => o.formats = vec![Format::None; 261],
            }
            assert_eq!(
                start(0, &o).err().map(|e| e.kind()),
                Some(ErrorKind::TooLarge)
            );
        }
        Ok(())
    }
}
