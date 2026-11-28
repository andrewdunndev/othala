//! Registration and authentication through the public API on a `MemStore`, the harness both none-attestation rows share.
use std::collections::BTreeMap;

use base::{BrowserBinding, Digest, Entropy, Secret, Slot, Store, UnixTime};
use sha2::{Digest as _, Sha256};
use store::MemStore;
use webauthn_rp::{
    Allow, Assertion, AuthenticationCeremony, AuthenticationOptions, AuthenticationResponse,
    CoseAlgorithm, CounterPolicy, Credential, CredentialId, CrossOrigin, DisplayName, Error, Key,
    Origin, Record, Registered, RegistrationCeremony, RegistrationOptions, RegistrationResponse,
    RelyingParty, Requirement, ResidentKey, RpId, Timeout, TrustDecision, TrustQuery, TrustSource,
    UserEntity, UserHandle, UserName,
};

pub(crate) const NOW: u64 = 1_000;

// the challenge first, then effect ids from a seeded source
pub(crate) struct Fixed(pub(crate) Vec<u8>, pub(crate) testkit::Seeded);

impl Entropy for Fixed {
    fn fill(&mut self, out: &mut [u8]) {
        if out.len() == self.0.len() {
            out.copy_from_slice(&self.0);
        } else {
            self.1.fill(out);
        }
    }
}

struct Unknown;

impl TrustSource for Unknown {
    fn decide(&self, _: &TrustQuery<'_>) -> TrustDecision<'_> {
        TrustDecision::Unknown
    }
}

pub(crate) fn relying_party(
    rp_id: &str,
    origin: &str,
    cross: CrossOrigin,
) -> Result<RelyingParty, &'static str> {
    let name = DisplayName::parse("Example").map_err(|_| "name")?;
    RelyingParty::builder(
        RpId::parse(rp_id).map_err(|_| "rp id")?,
        name,
        Origin::parse(origin).map_err(|_| "origin")?,
        CounterPolicy::Reject,
    )
    .cross_origin(cross)
    .build()
    .map_err(|_| "rp")
}

pub(crate) struct Registration<'a> {
    pub(crate) challenge: &'a [u8],
    pub(crate) client_data_json: &'a [u8],
    pub(crate) attestation_object: &'a [u8],
    pub(crate) requirement: Requirement,
    pub(crate) algorithms: &'a [CoseAlgorithm],
    /// The raw id the browser reports; the attested credential id when `None`.
    pub(crate) raw_id: Option<&'a [u8]>,
    /// The browser bindings the ceremony starts and finishes with; one fixed binding when `None`.
    pub(crate) browsers: Option<(&'a BrowserBinding, &'a BrowserBinding)>,
}

pub(crate) struct Registering {
    pub(crate) result: Result<Registered, Error>,
    pub(crate) left: BTreeMap<Key, Record>,
    pub(crate) finished: bool,
}

// the credential id an attestation object attests, read by its layout (L3 6.1, 6.5.1): the bytes after `authData`
pub(crate) fn attested_id(object: &[u8]) -> Vec<u8> {
    let marker = b"authData";
    let Some(at) = object.windows(marker.len()).position(|w| w == marker) else {
        return Vec::new();
    };
    let tail = object.get(at + marker.len()..).unwrap_or(&[]);
    let skip = match tail.first() {
        Some(0x58) => 2,
        Some(0x59) => 3,
        _ => return Vec::new(),
    };
    let body = tail.get(skip + 53..).unwrap_or(&[]);
    let len = body
        .get(..2)
        .and_then(|l| <[u8; 2]>::try_from(l).ok())
        .map_or(0, |l| usize::from(u16::from_be_bytes(l)));
    body.get(2..2 + len).unwrap_or(&[]).to_vec()
}

pub(crate) fn binding() -> BrowserBinding {
    BrowserBinding::from(&Secret::new([5; 32]))
}

pub(crate) fn register(
    store: &mut MemStore<Key, Record>,
    rp: &RelyingParty,
    r: &Registration<'_>,
) -> Result<Registering, &'static str> {
    let now = UnixTime::new(NOW);
    let mut ent = Fixed(r.challenge.to_vec(), testkit::seeded(1));
    let fixed = binding();
    let user = UserHandle::from_stored(b"user-handle").map_err(|_| "handle")?;
    let entity = UserEntity::new(
        user,
        UserName::parse("ada").map_err(|_| "name")?,
        DisplayName::parse("Ada").map_err(|_| "display")?,
    );
    let timeout = Timeout::from_secs(60).map_err(|_| "timeout")?;
    let options = r.algorithms.iter().fold(
        RegistrationOptions::new(r.requirement, ResidentKey::Preferred, timeout),
        |o, a| o.algorithm(*a),
    );
    let (started, finished) = r.browsers.unwrap_or((&fixed, &fixed));
    let (_, start) = rp
        .start_registration(&entity, &[], &options, started, now, &mut ent)
        .map_err(|_| "start")?;
    store
        .apply(&start, now)
        .map_err(|_| "start")?
        .map_err(|_| "start")?;
    let attested = attested_id(r.attestation_object);
    let raw_id = r.raw_id.unwrap_or(&attested);
    let response =
        match RegistrationResponse::new(raw_id, r.client_data_json, r.attestation_object, &[]) {
            Ok(response) => response,
            Err(result) => {
                return Ok(Registering {
                    result: Err(result),
                    left: store.contents(now),
                    finished: false,
                });
            }
        };
    // the started ceremony, as a host holding the session would load it, whatever challenge the response carries
    let started = Key::Ceremony(Digest::from_bytes(Sha256::digest(r.challenge).into()));
    let rows = store
        .load(core::slice::from_ref(&started), now)
        .map_err(|_| "load")?;
    let Some(Slot::Row(row)) = rows.get(&started) else {
        return Err("rows");
    };
    let state = RegistrationCeremony::from_row(row, |r| Some(r)).map_err(|_| "ceremony")?;
    let verdict = rp.finish_registration(state, &response, finished, &Unknown, now, &mut ent);
    let receipt = store
        .apply(verdict.effect(), now)
        .map_err(|_| "apply")?
        .map_err(|_| "apply")?;
    let result = verdict.settle(receipt).map_err(|_| "settle")?;
    Ok(Registering {
        result,
        left: store.contents(now),
        finished: true,
    })
}

pub(crate) struct Authentication<'a> {
    pub(crate) id: &'a CredentialId,
    pub(crate) user: &'a UserHandle,
    pub(crate) challenge: &'a [u8],
    pub(crate) client_data_json: &'a [u8],
    pub(crate) authenticator_data: &'a [u8],
    pub(crate) signature: &'a [u8],
}

pub(crate) fn authenticate(
    store: &mut MemStore<Key, Record>,
    rp: &RelyingParty,
    a: &Authentication<'_>,
) -> Result<Result<Assertion, Error>, &'static str> {
    let now = UnixTime::new(NOW);
    let mut ent = Fixed(a.challenge.to_vec(), testkit::seeded(7));
    let options = AuthenticationOptions::new(
        Requirement::Preferred,
        Timeout::from_secs(60).map_err(|_| "timeout")?,
    );
    let (_, start) = rp
        .start_authentication(
            Allow::User {
                user: a.user,
                credentials: &[],
            },
            &options,
            &binding(),
            now,
            &mut ent,
        )
        .map_err(|_| "start")?;
    store
        .apply(&start, now)
        .map_err(|_| "start")?
        .map_err(|_| "start")?;
    let response = match AuthenticationResponse::new(
        a.id.as_bytes(),
        a.client_data_json,
        a.authenticator_data,
        a.signature,
        Some(a.user.as_bytes()),
    ) {
        Ok(response) => response,
        Err(e) => return Ok(Err(e)),
    };
    let ceremony = Key::Ceremony(Digest::from_bytes(Sha256::digest(a.challenge).into()));
    let credential = Key::Credential(a.id.clone());
    let rows = store
        .load(&[ceremony.clone(), credential.clone()], now)
        .map_err(|_| "load")?;
    let (Some(Slot::Row(c)), Some(Slot::Row(s))) = (rows.get(&ceremony), rows.get(&credential))
    else {
        return Err("rows");
    };
    let state = AuthenticationCeremony::from_row(c, |r| Some(r)).map_err(|_| "ceremony")?;
    let stored = Credential::from_row(s, |r| Some(r)).map_err(|_| "stored")?;
    let verdict = rp.finish_authentication(state, stored, &response, &binding(), now, &mut ent);
    let receipt = store
        .apply(verdict.effect(), now)
        .map_err(|_| "apply")?
        .map_err(|_| "apply")?;
    verdict.settle(receipt).map_err(|_| "settle")
}
