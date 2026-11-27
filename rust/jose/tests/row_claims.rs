//! JWT claims under a policy (CONTRACT R31 to R37).
use base::UnixTime;
use jose::{Audience, Issuer, Jwt, Leeway, Policy, SecretJwk, TokenKind, Typ};
use serde::Deserialize;
use testkit::vector;
use testkit::vectors::{Json, Outcome, run};

#[derive(Deserialize)]
struct Claims {}

struct AccessToken;

impl TokenKind for AccessToken {
    const TYP: Typ = Typ::Explicit("at+jwt");
    type Claims = Claims;
}

#[derive(Deserialize)]
struct Settings {
    iss: String,
    aud: String,
    leeway: u64,
}

#[derive(Deserialize)]
struct Expect {
    ok: bool,
    kind: Option<String>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    jwk: Json,
    jwt: String,
    policy: Settings,
    now: u64,
    expect: Expect,
}

#[test]
fn claims_cases() {
    let tally = run::<Case>(vector!("jose-derived/claims.json"), 23, |case| {
        let policy = Issuer::new(&case.policy.iss).and_then(|iss| {
            Policy::<AccessToken>::new(
                iss,
                Audience::new(&case.policy.aud)?,
                Leeway::new(case.policy.leeway)?,
            )
        });
        let outcome = SecretJwk::decode(case.jwk.text().as_bytes())
            .and_then(|key| key.verify_key::<jose::Hs256>())
            .and_then(|key| Jwt::parse(&case.jwt)?.verify(&key))
            .and_then(|jwt| jwt.claims(&policy?, UnixTime::new(case.now)));
        testkit::vectors::assert_verdict(
            &outcome,
            case.expect.ok,
            case.expect.kind.as_deref(),
            |e| e.kind(),
            &case.id,
        );
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (23, 23));
}
