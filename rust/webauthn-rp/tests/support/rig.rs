//! A virtual ES256 authenticator, the relying party it talks to and the entropy that fixes a challenge.
use base::{BrowserBinding, Entropy, Secret};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest as _, Sha256};
use webauthn_rp::{
    CounterPolicy, DisplayName, Origin, RelyingParty, RpId, TrustDecision, TrustQuery, TrustSource,
};

pub(crate) const NOW: u64 = 1_000;
pub(crate) const ID: &[u8] = b"virtual-credential";
pub(crate) const USER: &[u8] = b"user-handle";

pub(crate) struct Unknown;

impl TrustSource for Unknown {
    fn decide(&self, _: &TrustQuery<'_>) -> TrustDecision<'_> {
        TrustDecision::Unknown
    }
}

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

pub(crate) fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(crate) fn client_data(kind: &str, challenge: &[u8]) -> Vec<u8> {
    format!(
        r#"{{"type":"{kind}","challenge":"{}","origin":"https://example.org"}}"#,
        base::b64url_encode(challenge)
    )
    .into_bytes()
}

// the authenticator: an ES256 key, a counter and the data it signs
pub(crate) struct Virtual {
    pub(crate) key: SigningKey,
    pub(crate) count: u32,
}

impl Virtual {
    pub(crate) fn cose(&self) -> Result<Vec<u8>, &'static str> {
        let point = self.key.verifying_key().to_sec1_point(false);
        let (x, y) = (point.x().ok_or("x")?, point.y().ok_or("y")?);
        Ok([
            &[0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20][..],
            x,
            &[0x22, 0x58, 0x20],
            y,
        ]
        .concat())
    }

    // `none` attestation (L3 8.7): the three members of the attestation object around the attested authenticator data
    pub(crate) fn create(&self, challenge: &[u8]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        let data = [
            &sha(b"example.org")[..],
            &[0x45],
            &self.count.to_be_bytes(),
            &[7; 16],
            &[0, u8::try_from(ID.len()).map_err(|_| "id")?],
            ID,
            &self.cose()?,
        ]
        .concat();
        let object = [
            &[0xa3, 0x63][..],
            b"fmt",
            &[0x64],
            b"none",
            &[0x67],
            b"attStmt",
            &[0xa0, 0x68],
            b"authData",
            &[0x58, u8::try_from(data.len()).map_err(|_| "data")?],
            &data,
        ]
        .concat();
        Ok((client_data("webauthn.create", challenge), object))
    }

    pub(crate) fn get(&mut self, challenge: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        self.count += 1;
        let data = [&sha(b"example.org")[..], &[0x05], &self.count.to_be_bytes()].concat();
        let json = client_data("webauthn.get", challenge);
        let signature: Signature = self.key.sign(&[data.as_slice(), &sha(&json)].concat());
        (json, data, signature.to_der().as_bytes().to_vec())
    }
}

pub(crate) fn rp() -> Result<RelyingParty, &'static str> {
    let name = DisplayName::parse("Example").map_err(|_| "name")?;
    let origin = Origin::parse("https://example.org").map_err(|_| "origin")?;
    RelyingParty::builder(
        RpId::parse("example.org").map_err(|_| "rp id")?,
        name,
        origin,
        CounterPolicy::Reject,
    )
    .build()
    .map_err(|_| "rp")
}

pub(crate) fn binding() -> BrowserBinding {
    BrowserBinding::from(&Secret::new([5; 32]))
}
