//! Golden v1 stored records (CONTRACT R147): the committed bytes of each record shape, decoded to their stated values and re-encoded byte for byte.
//!
//! Origin: each `golden/*.hex` is `Record::encode` of the record the `record.rs` unit tests build with the same name, written from the encoder on origin/main at 669c6adb, before the tag tables were generated from one list.
//! `golden/debug.txt` holds the `Debug` text of each decoded record, one line per fixture, from the same run.
//! A deliberate format change adds a new version and new fixtures; these files stay as the proof that v1 rows still read.
use webauthn_rp::{
    Aaguid, AttestationType, Backup, BackupState, CoseAlgorithm, Format, Record, Transport, Trust,
    UserVerification,
};

const NAMES: [&str; 9] = [
    "registration",
    "registration_conditional",
    "authentication",
    "authentication_plain",
    "credential_es256",
    "credential_es384",
    "credential_eddsa",
    "credential_rs256",
    "credential_single_device",
];

fn dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    text.trim()
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

fn golden(name: &str) -> Vec<u8> {
    let files = testkit::fixture::files(&dir());
    let hex = files.iter().find(|(f, _)| f == &format!("{name}.hex"));
    let text = hex.and_then(|(_, b)| String::from_utf8(b.clone()).ok());
    text.and_then(|t| unhex(&t)).unwrap_or_default()
}

fn decoded(name: &str) -> Record {
    match Record::decode(&golden(name)) {
        Ok(record) => record,
        Err(e) => panic!("{name}: {e}"),
    }
}

#[test]
fn every_fixture_is_listed_and_every_name_has_a_fixture() {
    let mut on_disk: Vec<String> = testkit::fixture::files(&dir())
        .into_iter()
        .filter_map(|(f, _)| f.strip_suffix(".hex").map(str::to_owned))
        .collect();
    on_disk.sort();
    let mut listed: Vec<String> = NAMES.iter().map(|n| (*n).to_owned()).collect();
    listed.sort();
    assert_eq!(on_disk, listed);
}

#[test]
fn committed_v1_bytes_re_encode_byte_for_byte() {
    for name in NAMES {
        let bytes = golden(name);
        assert_eq!(bytes.first(), Some(&1), "{name}: version byte");
        assert_eq!(decoded(name).encode().as_deref(), Ok(&bytes[..]), "{name}");
    }
}

#[test]
fn committed_v1_bytes_decode_to_their_stated_values() {
    let shown: Vec<String> = NAMES
        .iter()
        .map(|n| format!("{n}: {:?}\n", decoded(n)))
        .collect();
    assert_eq!(shown.concat(), include_str!("golden/debug.txt"));
}

#[test]
fn the_credential_fixture_reads_through_the_public_accessors() {
    let Record::Credential(c) = decoded("credential_es256") else {
        panic!("not a credential");
    };
    assert_eq!(c.id().as_bytes(), b"credential");
    assert_eq!(c.user().as_bytes(), b"user");
    assert_eq!(c.sign_count(), 0x0102_0304);
    assert_eq!(c.algorithm(), CoseAlgorithm::Es256);
    assert_eq!(c.uv_initialized(), UserVerification::PresenceOnly);
    assert_eq!(c.backup(), Backup::MultiDevice(BackupState::BackedUp));
    assert_eq!(c.transports(), &[Transport::Usb, Transport::Internal]);
    assert_eq!(c.aaguid(), Aaguid::from_bytes([6; 16]));
    assert_eq!(c.attestation().format(), Format::Packed);
    assert_eq!(c.attestation().kind(), AttestationType::AttCa);
    assert_eq!(c.attestation().trust(), Trust::Anchored);
    assert_eq!(c.attestation().chain().len(), 2);
}
