//! Key binding, JWK Sets and JWK serialization (CONTRACT R13, R16 to R21, R26, R27, R30).
mod common_figures;

use std::collections::BTreeMap;

use jose::{
    Alg, AnySigningKey, AnyVerifyKey, EdDsa, Error, Es256, Es384, Hs256, Hs384, Hs512, Jwk,
    JwkEntry, JwkSet, Jws, Kid, Kty, Rs256, SecretJwk, SigningAlg, VerifyKey,
};
use proptest::prelude::*;
use proptest::test_runner::{RngSeed, TestError, TestRunner};
use serde::Deserialize;
use testkit::vector;
use testkit::vectors::{Json, Outcome, run};

fn bound<A: Alg>(key: Result<VerifyKey<A>, Error>) -> Result<(), Error> {
    key.map(|_| ())
}

/// Builds the verification key `jwk` holds for `alg`: an `oct` key for HS, a public key for the rest.
fn key_check(alg: &str, jwk: &str) -> Result<(), Error> {
    let (secret, public) = (
        SecretJwk::decode(jwk.as_bytes()),
        Jwk::decode(jwk.as_bytes()),
    );
    match alg {
        "HS256" => bound::<Hs256>(secret.and_then(|k| k.verify_key())),
        "HS384" => bound::<Hs384>(secret.and_then(|k| k.verify_key())),
        "HS512" => bound::<Hs512>(secret.and_then(|k| k.verify_key())),
        "RS256" => bound::<Rs256>(public.and_then(|k| k.verify_key())),
        "ES256" => bound::<Es256>(public.and_then(|k| k.verify_key())),
        "ES384" => bound::<Es384>(public.and_then(|k| k.verify_key())),
        "EdDSA" => bound::<EdDsa>(public.and_then(|k| k.verify_key())),
        _ => Err(jose::ErrorKind::UnsupportedAlg.into()),
    }
}

type Draw = (usize, String, usize, usize, usize);

#[derive(Deserialize)]
struct Expect {
    ok: bool,
    kind: Option<String>,
    keys: Option<usize>,
    kty: Option<String>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    op: String,
    alg: Option<String>,
    jwk: Option<Json>,
    jwks: Option<Json>,
    jwks_json: Option<String>,
    kid: Option<String>,
    expect: Expect,
}

fn named(expect: &Expect, outcome: Result<(), jose::Error>, id: &str) {
    testkit::vectors::assert_verdict(
        &outcome,
        expect.ok,
        expect.kind.as_deref(),
        |e| e.kind(),
        id,
    );
}

#[test]
fn key_cases() {
    let tally = run::<Case>(vector!("jose-derived/keys.json"), 29, |case| {
        let (alg, jwk) = (
            case.alg.as_deref().unwrap_or_default(),
            case.jwk.as_ref().map_or("", Json::text),
        );
        let outcome = match case.op.as_str() {
            "jwk_verify_key" => key_check(alg, jwk),
            _ if jwk.contains(r#""oct""#) => SecretJwk::decode(jwk.as_bytes())
                .and_then(|key| AnySigningKey::from_jwk(&key))
                .map(|_| ()),
            _ => Jwk::decode(jwk.as_bytes())
                .and_then(|key| AnyVerifyKey::from_jwk(&key))
                .map(|_| ()),
        };
        named(&case.expect, outcome, &case.id);
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (29, 29));
}

#[test]
fn jwk_sets() {
    let tally = run::<Case>(vector!("jose-derived/jwks.json"), 8, |case| {
        let text = case
            .jwks
            .as_ref()
            .map(Json::text)
            .or(case.jwks_json.as_deref())
            .unwrap_or_default();
        let set = JwkSet::decode(text.as_bytes());
        if case.op == "jwks_decode" {
            let count = set.as_ref().map(|set| set.entries().len()).ok();
            assert_eq!(
                count,
                case.expect.keys.filter(|_| case.expect.ok),
                "{}",
                case.id
            );
            named(&case.expect, set.map(|_| ()), &case.id);
            return Outcome::Checked;
        }
        let entry = set.and_then(|set| {
            let kid = Kid::new(case.kid.as_deref().unwrap_or_default())?;
            set.find(&kid).map(|entry| match entry {
                JwkEntry::Public(key) => key.kty(),
                JwkEntry::Secret(key) => key.kty(),
                _ => Kty::Oct,
            })
        });
        if let Some(kty) = &case.expect.kty {
            let want = if kty == "oct" { Kty::Oct } else { Kty::Rsa };
            assert_eq!(entry.as_ref().ok(), Some(&want), "{}", case.id);
        }
        named(&case.expect, entry.map(|_| ()), &case.id);
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (8, 8));
}

/// The public keys of keys.json by case id.
fn public_keys() -> BTreeMap<String, String> {
    let mut found = BTreeMap::new();
    let tally = run::<Case>(vector!("jose-derived/keys.json"), 1, |case| {
        if [
            "es256-p256",
            "es256-p384-key",
            "es256-p521-key",
            "rs256-2048",
            "eddsa-ed25519",
        ]
        .contains(&case.id.as_str())
        {
            found.insert(
                case.id.clone(),
                case.jwk
                    .as_ref()
                    .map_or_else(String::new, |j| j.text().to_owned()),
            );
        }
        Outcome::Checked
    });
    assert_eq!(tally.checked(), tally.total());
    found
}

#[test]
fn jwk_round_trip() -> Result<(), TestError<Draw>> {
    let keys: Vec<String> = public_keys().into_values().collect();
    assert_eq!(keys.len(), 5);
    let keys: Vec<String> = keys
        .into_iter()
        .filter(|k| cfg!(feature = "es512") || !k.contains("P-521"))
        .collect();
    let algs = [
        "ES256", "ES384", "RS256", "PS512", "EdDSA", "A128KW", "ECDH-ES", "A256GCM",
    ];
    let uses = ["", r#","use":"sig""#, r#","use":"enc""#];
    let ops = [
        "",
        r#","key_ops":["verify"]"#,
        r#","key_ops":["encrypt","deriveKey"]"#,
    ];
    let config = ProptestConfig {
        cases: 128,
        rng_seed: RngSeed::Fixed(0x5eed_0003),
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    TestRunner::new(config).run(
        &(
            0..keys.len(),
            "[a-zA-Z0-9 \"\\\\/-]{0,30}",
            0..algs.len() + 1,
            0..uses.len(),
            0..ops.len(),
        ),
        |(key, kid, alg, usage, op)| {
            let base = keys
                .get(key)
                .map(|k| k.trim_end().trim_end_matches('}'))
                .unwrap_or_default();
            let kid_member = if kid.is_empty() {
                String::new()
            } else {
                format!(
                    r#","kid":{}"#,
                    serde_json::to_string(&kid).unwrap_or_default()
                )
            };
            let alg_member = algs
                .get(alg)
                .map(|a| format!(r#","alg":"{a}""#))
                .unwrap_or_default();
            let usage_member = uses.get(usage).copied().unwrap_or_default();
            let ops_member = ops.get(op).copied().unwrap_or_default();
            let text = format!("{base}{kid_member}{alg_member}{usage_member}{ops_member}}}");
            let Ok(first) = Jwk::decode(text.as_bytes()) else {
                // a `use` that disagrees with `key_ops` is refused, the one decode failure here
                prop_assert!(usage > 0 && op > 0, "{text}");
                return Ok(());
            };
            let written = serde_json::to_string(&first).unwrap_or_default();
            let second = Jwk::decode(written.as_bytes());
            prop_assert_eq!(second.as_ref().err().map(|e| e.kind()), None, "{}", written);
            let second = second.map_err(|_| TestCaseError::fail("decode"))?;
            prop_assert_eq!(first.kid(), second.kid());
            prop_assert_eq!(first.sig_alg(), second.sig_alg());
            prop_assert_eq!(first.thumbprint(), second.thumbprint());
            prop_assert_eq!(
                serde_json::to_string(&second).unwrap_or_default(),
                written.clone()
            );
            let set = JwkSet::new(vec![first]).map_err(|_| TestCaseError::fail("set"))?;
            let set_text = serde_json::to_string(&set).unwrap_or_default();
            prop_assert_eq!(set_text, format!(r#"{{"keys":[{written}]}}"#));
            Ok(())
        },
    )
}

#[test]
fn sets_refuse_a_repeated_kid() {
    let keys = public_keys();
    let key = |kid: &str| {
        let base = keys
            .get("es256-p256")
            .map(|k| k.trim_end().trim_end_matches('}'))
            .unwrap_or_default();
        Jwk::decode(format!(r#"{base},"kid":"{kid}"}}"#).as_bytes())
    };
    let kinds = |a: &str, b: &str| {
        let both = vec![key(a).ok(), key(b).ok()]
            .into_iter()
            .flatten()
            .collect();
        JwkSet::new(both).err().map(|e| format!("{:?}", e.kind()))
    };
    assert_eq!(kinds("a", "a"), Some("DuplicateMember".to_owned()));
    assert_eq!(kinds("a", "b"), None);
    let too_many = (0..33).filter_map(|i| key(&format!("k{i}")).ok()).collect();
    assert_eq!(
        JwkSet::new(too_many)
            .err()
            .map(|e| format!("{:?}", e.kind())),
        Some("TooLarge".to_owned())
    );
}

#[test]
fn a_private_key_keeps_its_public_members() {
    let file = common_figures::all(vector!("rfc7520/jwk.json"));
    let private = file
        .examples
        .iter()
        .find(|e| e.example == "3.4")
        .and_then(|e| e.figures.last())
        .and_then(|f| f.json.as_ref());
    let secret = private.and_then(|j| SecretJwk::decode(j.text().as_bytes()).ok());
    let public = secret.as_ref().and_then(SecretJwk::public);
    assert_eq!(
        public.as_ref().and_then(|k| k.kid()).map(Kid::as_str),
        Some("bilbo.baggins@hobbiton.example")
    );
    let written = serde_json::to_string(&public).unwrap_or_default();
    assert!(
        written.contains(r#""use":"sig""#) && !written.contains(r#""d""#),
        "{written}"
    );
    assert_eq!(
        secret.map(|s| s.thumbprint()),
        public.map(|p| p.thumbprint())
    );
}

#[test]
fn any_key_verifies_under_its_own_algorithm_only() {
    let keys = public_keys();
    let pairs = [
        ("es256-p256", SigningAlg::Es256),
        ("es256-p384-key", SigningAlg::Es384),
        ("eddsa-ed25519", SigningAlg::EdDsa),
        ("rs256-2048", SigningAlg::Rs256),
        ("rs256-2048", SigningAlg::Rs384),
        ("rs256-2048", SigningAlg::Rs512),
        ("rs256-2048", SigningAlg::Ps256),
        ("rs256-2048", SigningAlg::Ps384),
        ("rs256-2048", SigningAlg::Ps512),
    ];
    #[cfg(feature = "es512")]
    let pairs = [pairs.as_slice(), &[("es256-p521-key", SigningAlg::Es512)]].concat();
    for (id, alg) in pairs {
        let jwk = keys
            .get(id)
            .and_then(|text| Jwk::decode(text.as_bytes()).ok());
        let key = jwk.and_then(|jwk| AnyVerifyKey::from_jwk_for(&jwk, alg).ok());
        assert_eq!(key.as_ref().map(AnyVerifyKey::alg), Some(alg), "{id}");
        let token = |name: &str| {
            let header = base::b64url_encode(format!(r#"{{"alg":"{name}"}}"#).as_bytes());
            format!("{header}.e30.AA")
        };
        let kind = |name: &str| {
            let text = token(name);
            let verified = Jws::parse(&text)
                .and_then(|jws| jws.verify_any(key.as_ref().ok_or(jose::ErrorKind::Malformed)?));
            verified.err().map(|e| format!("{:?}", e.kind()))
        };
        assert_eq!(
            kind(alg.name()),
            Some("BadSignature".to_owned()),
            "{}",
            alg.name()
        );
        assert_eq!(
            kind("HS256"),
            Some("AlgMismatch".to_owned()),
            "{}",
            alg.name()
        );
    }
}
