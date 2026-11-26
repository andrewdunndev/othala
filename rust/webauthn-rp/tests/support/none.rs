//! W3C L3 section 16.2 and 16.4 to 16.6: registration with no attestation, then the authentication the section carries.
use serde::Deserialize;
use sha2::{Digest, Sha256};
use store::MemStore;
use webauthn_rp::{
    Counter, CredentialId, CrossOrigin, ErrorKind, Key, Record, Requirement, SpecStep, UserHandle,
};

use crate::ceremony::{Authentication, Registration, authenticate, register, relying_party};

#[derive(Deserialize)]
struct Item {
    name: Option<String>,
    hex: Option<String>,
}

#[derive(Deserialize)]
struct Block {
    phase: String,
    pre: Vec<Item>,
}

#[derive(Deserialize)]
pub(crate) struct Section {
    section: String,
    blocks: Vec<Block>,
}

fn field(block: &Block, name: &str) -> Vec<u8> {
    let text = block
        .pre
        .iter()
        .find(|i| i.name.as_deref() == Some(name))
        .and_then(|i| i.hex.as_deref())
        .unwrap_or("");
    (0..text.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

#[derive(Deserialize)]
struct File {
    sections: Vec<Section>,
}

const FILE: &str = include_str!("../../../vectors/w3c-webauthn-3/none.json");

// the testkit runner reads `cases` files; this one has `sections`, so its hash is checked against SOURCES.toml here
fn sections() -> Vec<Section> {
    let sha: String = Sha256::digest(FILE)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(
        include_str!("../../../vectors/SOURCES.toml").contains(&sha),
        "none.json is the file SOURCES.toml lists"
    );
    serde_json::from_str::<File>(FILE)
        .map(|f| f.sections)
        .unwrap_or_default()
}

pub(crate) fn cases() {
    let all = sections();
    assert_eq!(all.len(), 4);
    for s in &all {
        check(s);
    }
}

fn check(s: &Section) {
    {
        let (Some(reg), Some(auth)) = (
            s.blocks.iter().find(|b| b.phase == "registration"),
            s.blocks.iter().find(|b| b.phase == "authentication"),
        ) else {
            return;
        };
        // 16.4 and 16.5 are sent from a cross-origin frame, which is refused unless the relying party allows it
        let cross_origin = matches!(s.section.as_str(), "16.4" | "16.5");
        let registration = Registration {
            challenge: &field(reg, "challenge"),
            client_data_json: &field(reg, "clientDataJSON"),
            attestation_object: &field(reg, "attestationObject"),
            requirement: Requirement::Preferred,
            algorithms: &[],
        };
        let mut denied: MemStore<Key, Record> = MemStore::default();
        let strict = relying_party("example.org", "https://example.org", CrossOrigin::Deny);
        let Ok(strict) = strict else {
            return;
        };
        let refused = register(&mut denied, &strict, &registration);
        let refusal = refused.as_ref().ok().and_then(|r| r.result.as_ref().err());
        let nothing = refused
            .as_ref()
            .is_ok_and(|r| r.finished && r.left.is_empty());
        assert!(
            refusal.is_none() || nothing,
            "{}: a refusal registers nothing",
            s.section
        );
        assert_eq!(
            refusal.map(|e| (e.kind(), e.spec_step())),
            cross_origin.then_some((
                ErrorKind::CrossOriginDenied,
                Some(SpecStep::Registration(10))
            )),
            "{}",
            s.section
        );
        let permissive = relying_party("example.org", "https://example.org", CrossOrigin::AnyTop);
        let Ok(permissive) = permissive else {
            return;
        };
        let mut store: MemStore<Key, Record> = MemStore::default();
        let done = register(&mut store, &permissive, &registration);
        assert_eq!(done.as_ref().err(), None, "{}", s.section);
        let Ok(done) = done else {
            return;
        };
        let registered = done.result;
        assert_eq!(registered.as_ref().err(), None, "{}", s.section);
        let Ok(registered) = registered else {
            return;
        };
        assert_eq!(
            registered.credential().id().as_bytes(),
            field(reg, "credential_id").as_slice(),
            "{}",
            s.section
        );
        assert_eq!(
            registered.credential().aaguid().as_bytes().as_slice(),
            field(reg, "aaguid").as_slice(),
            "{}",
            s.section
        );
        let id = CredentialId::from_bytes(registered.credential().id().as_bytes());
        let user = UserHandle::from_stored(b"user-handle");
        let (Ok(id), Ok(user)) = (id, user) else {
            return;
        };
        let authentication = Authentication {
            id: &id,
            user: &user,
            challenge: &field(auth, "challenge"),
            client_data_json: &field(auth, "clientDataJSON"),
            authenticator_data: &field(auth, "authenticatorData"),
            signature: &field(auth, "signature"),
        };
        let verified = authenticate(&mut store, &permissive, &authentication);
        assert_eq!(verified.as_ref().err(), None, "{}", s.section);
        let Ok(verified) = verified else {
            return;
        };
        assert_eq!(verified.as_ref().err(), None, "{}", s.section);
        assert_eq!(
            verified.map(|a| a.counter()),
            Ok(Counter::Unsupported),
            "{}",
            s.section
        );
        let mut store: MemStore<Key, Record> = MemStore::default();
        let (Ok(_), Ok(_)) = (
            register(&mut store, &permissive, &registration),
            Ok::<(), ()>(()),
        ) else {
            return;
        };
        let again = authenticate(&mut store, &strict, &authentication);
        let again = again.ok().and_then(Result::err);
        let want = cross_origin.then_some((
            ErrorKind::CrossOriginDenied,
            Some(SpecStep::Authentication(13)),
        ));
        assert_eq!(
            again.map(|e| (e.kind(), e.spec_step())),
            want,
            "{}",
            s.section
        );
    }
}
