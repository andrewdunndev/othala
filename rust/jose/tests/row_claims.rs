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

//= https://www.rfc-editor.org/rfc/rfc7519#section-4
//= type=test
//# The Claim Names within a JWT Claims Set MUST be unique; JWT parsers MUST either reject JWTs with
//# duplicate Claim Names or use a JSON parser that returns only the lexically last duplicate member
//# name, as specified in Section 15.12 ("The JSON Object") of ECMAScript 5.1 [ECMAScript].
//= https://www.rfc-editor.org/rfc/rfc7519#section-7.2
//= type=test
//# If any of the listed steps fail, then the JWT MUST be rejected -- that is, treated by the
//# application as an invalid input.
//= https://www.rfc-editor.org/rfc/rfc7519#section-7.3
//= type=test
//# These comparison rules MUST be used for all JSON string comparisons except in cases where the
//# definition of the member explicitly calls out that a different comparison rule is to be used for
//# that member value.
//= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3
//= type=test
//# Each principal intended to process the JWT MUST identify itself with a value in the audience
//# claim.
//= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3
//= type=test
//# If the principal processing the claim does not identify itself with a value in the "aud" claim
//# when this claim is present, then the JWT MUST be rejected.
//= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4
//= type=test
//# The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST
//# NOT be accepted for processing.
//= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4
//= type=test
//# The processing of the "exp" claim requires that the current date/time MUST be before the
//# expiration date/time listed in the "exp" claim.
//= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4
//= type=test
//# Its value MUST be a number containing a NumericDate value.
//= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5
//= type=test
//# The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for
//# processing.
//= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5
//= type=test
//# The processing of the "nbf" claim requires that the current date/time MUST be after or equal to
//# the not-before date/time listed in the "nbf" claim.
//= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5
//= type=test
//# Its value MUST be a number containing a NumericDate value.
//= https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6
//= type=test
//# Its value MUST be a number containing a NumericDate value.
#[test]
fn claims_cases() {
    let tally = run::<Case>(vector!("jose-derived/claims.json"), 25, |case| {
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
    assert_eq!((tally.total(), tally.checked()), (25, 25));
}
