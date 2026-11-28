//! The oracle's `limits.json`: each bound at its value is accepted and one past it is refused, by the reader its op names.
use base::UnixTime;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use testkit::vectors::{Outcome, run};
use webauthn_rp::{
    Allow, AuthenticationOptions, AuthenticationResponse, CounterPolicy, CredentialDescriptor,
    CredentialId, DisplayName, Error, Origin, RegistrationOptions, RegistrationResponse,
    RelyingParty, Requirement, ResidentKey, RpId, SpecStep, Timeout, UserEntity, UserHandle,
    UserName,
};

use crate::cbor::{Order, decode};
use crate::ceremony::{Fixed, attested_id, binding};
use crate::hex::{hex_list, hex_opt};
use crate::refusal::Refusal;

#[derive(Deserialize)]
struct Expect {
    ok: bool,
    #[serde(flatten)]
    refusal: Refusal,
}

#[derive(Deserialize)]
struct Name {
    name: String,
    display_name: String,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    op: String,
    unbuilt: Option<String>,
    // the bytes of the case: hex up to 4096, base64url above, with the length and SHA-256 they must have; a text value for an RP ID or AppID
    input: Option<String>,
    input_b64url: Option<String>,
    input_len: Option<usize>,
    input_sha256: Option<String>,
    #[serde(default, deserialize_with = "hex_list")]
    exclude_credentials: Vec<Vec<u8>>,
    #[serde(default, deserialize_with = "hex_list")]
    allow_credentials: Vec<Vec<u8>>,
    origins: Option<Vec<String>>,
    timeout_secs: Option<u32>,
    user: Option<Name>,
    #[serde(default, deserialize_with = "hex_opt")]
    signature: Option<Vec<u8>>,
    expect: Expect,
}

const NOW: UnixTime = UnixTime::new(1_000);
const CHALLENGE: &str = "EijdmqrPNtPCSCR4aUB_y-czWE3Q7fYuiakE10n5Mdc";

fn client_data(kind: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"webauthn.{kind}","challenge":"{CHALLENGE}","origin":"https://example.org","crossOrigin":false}}"#
    )
    .into_bytes()
}

// the rpIdHash, the UP flag and a zero counter
fn authenticator_data() -> Vec<u8> {
    [&Sha256::digest(b"example.org")[..], &[1], &[0; 4]].concat()
}

impl Case {
    fn bytes(&self) -> Vec<u8> {
        let bytes = match (&self.input_b64url, &self.input) {
            // `MAX_B64URL_TEXT` is a multiple of four, so each chunk of the text decodes on its own
            (Some(text), _) => text
                .as_bytes()
                .chunks(base::MAX_B64URL_TEXT)
                .map(|chunk| {
                    std::str::from_utf8(chunk)
                        .ok()
                        .and_then(|t| base::b64url_decode(t).ok())
                })
                .collect::<Option<Vec<_>>>()
                .unwrap_or_default()
                .concat(),
            (None, Some(text)) => (0..text.len())
                .step_by(2)
                .filter_map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
                .collect(),
            (None, None) => Vec::new(),
        };
        if let Some(len) = self.input_len {
            assert_eq!(bytes.len(), len, "{}: the case's length", self.id);
        }
        if let Some(digest) = &self.input_sha256 {
            let seen: String = Sha256::digest(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(&seen, digest, "{}: the case's SHA-256", self.id);
        }
        bytes
    }

    fn text(&self) -> &str {
        self.input.as_deref().unwrap_or_default()
    }
}

fn descriptors(ids: &[Vec<u8>]) -> Result<Vec<CredentialDescriptor>, Error> {
    ids.iter()
        .map(|id| CredentialId::from_bytes(id).map(|id| CredentialDescriptor::new(id, &[])))
        .collect()
}

fn relying_party(origins: &[String]) -> Result<RelyingParty, Error> {
    let mut all = origins.iter().map(|o| Origin::parse(o));
    let first = all
        .next()
        .unwrap_or_else(|| Origin::parse("https://example.org"))?;
    let builder = RelyingParty::builder(
        RpId::parse("example.org")?,
        DisplayName::parse("Example")?,
        first,
        CounterPolicy::Reject,
    );
    all.try_fold(builder, |b, o| o.map(|o| b.origin(o)))?
        .build()
}

fn start_registration(c: &Case) -> Result<(), Error> {
    let rp = relying_party(&[])?;
    let user = c.user.as_ref().map_or_else(
        || Ok((UserName::parse("ada")?, DisplayName::parse("Ada")?)),
        |u| {
            Ok((
                UserName::parse(&u.name)?,
                DisplayName::parse(&u.display_name)?,
            ))
        },
    )?;
    let entity = UserEntity::new(UserHandle::from_stored(b"user-handle")?, user.0, user.1);
    let timeout = Timeout::from_secs(c.timeout_secs.unwrap_or(60))?;
    let options = RegistrationOptions::new(Requirement::Preferred, ResidentKey::Preferred, timeout);
    let exclude = descriptors(&c.exclude_credentials)?;
    let mut entropy = Fixed(vec![9; 32], testkit::seeded(1));
    rp.start_registration(&entity, &exclude, &options, &binding(), NOW, &mut entropy)
        .map(|_| ())
}

fn start_authentication(c: &Case) -> Result<(), Error> {
    let rp = relying_party(&[])?;
    let user = UserHandle::from_stored(b"user-handle")?;
    let listed = descriptors(&c.allow_credentials)?;
    let options = AuthenticationOptions::new(Requirement::Preferred, Timeout::from_secs(60)?);
    let mut entropy = Fixed(vec![9; 32], testkit::seeded(1));
    let allow = Allow::User {
        user: &user,
        credentials: &listed,
    };
    rp.start_authentication(allow, &options, &binding(), NOW, &mut entropy)
        .map(|_| ())
}

// the kind and the step of a refusal, as `Debug` text, since the crate's `Error` and the one `src/` compiles into this test are two types; `None` for an op no reader here reads
fn read(c: &Case) -> Option<Result<(), (String, String)>> {
    let seen = |e: &Error| (format!("{:?}", e.kind()), format!("{:?}", e.spec_step()));
    read_as(c).map(|read| read.map_err(|e| seen(&e)))
}

fn read_as(c: &Case) -> Option<Result<(), Error>> {
    let (ad, get) = (authenticator_data(), client_data("get"));
    let assertion = |cdj: &[u8], ad: &[u8], sig: &[u8]| {
        AuthenticationResponse::new(b"id", cdj, ad, sig, None).map(|_| ())
    };
    let read = match c.op.as_str() {
        "client_data" => assertion(&c.bytes(), &ad, b"sig"),
        "authenticator_data" => assertion(&get, &c.bytes(), b"sig"),
        "assertion_response" => assertion(&get, &ad, &c.signature.clone().unwrap_or_default()),
        "attestation_object" => {
            let object = c.bytes();
            RegistrationResponse::new(&attested_id(&object), &client_data("create"), &object, &[])
                .map(|_| ())
        }
        "rp_id_parse" => RpId::parse(c.text()).map(|_| ()),
        "user_handle_from_stored" => UserHandle::from_stored(&c.bytes()).map(|_| ()),
        "relying_party_build" => {
            relying_party(c.origins.as_deref().unwrap_or_default()).map(|_| ())
        }
        "start_registration" => start_registration(c),
        "start_authentication" => start_authentication(c),
        _ => return None,
    };
    Some(read)
}

// the numbering of the steps an op's refusal carries
fn numbered(op: &str) -> Option<fn(u8) -> SpecStep> {
    match op {
        "attestation_object" | "start_registration" => Some(SpecStep::Registration),
        "client_data" | "authenticator_data" | "assertion_response" | "start_authentication" => {
            Some(SpecStep::Authentication)
        }
        _ => None,
    }
}

pub(crate) fn cases() {
    let tally = run::<Case>(
        testkit::vector!("webauthn-rp-derived/limits.json"),
        30,
        |c| {
            if c.unbuilt.is_some() {
                return Outcome::NotApplicable;
            }
            let read = match c.op.as_str() {
                "cbor_limit" => Some(
                    decode(&c.bytes(), Order::Canonical)
                        .map(|_| ())
                        .map_err(|e| (format!("{:?}", e.kind()), format!("{:?}", e.spec_step()))),
                ),
                _ => read(c),
            };
            let Some(read) = read else {
                return Outcome::NotApplicable;
            };
            match read {
                Ok(()) => assert!(c.expect.ok, "{}: accepted", c.id),
                Err((kind, step)) => {
                    assert!(!c.expect.ok, "{}: refused as {kind}", c.id);
                    c.expect
                        .refusal
                        .check_seen(&c.id, numbered(&c.op), &kind, &step);
                }
            }
            Outcome::Checked
        },
    );
    assert_eq!((tally.total(), tally.checked()), (48, 30));
}
