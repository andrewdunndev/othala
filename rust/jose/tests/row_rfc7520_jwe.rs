//! RFC 7520 section 5 JWEs in each serialization given (CONTRACT R49, R52); ECDH-ES and RSA-OAEP are counted not
//! applicable here and checked in `row_rfc7520_jwe_ecdh` and `row_oaep`.
mod common_jwe;
mod common_refusal;

use base::b64url_encode;
use jose::{ErrorKind, Jwe, JweAlg};
use serde::Deserialize;
use testkit::vector;
use testkit::vectors::{Json, Outcome, run};

#[derive(Deserialize)]
struct Expect {
    ok: bool,
    plaintext: Option<String>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    alg: String,
    enc: String,
    serialization: String,
    jwk: Option<Json>,
    jwe: Json,
    expect: Expect,
}

fn parse(compact: bool, wire: &str) -> Result<Jwe<'_>, jose::Error> {
    if compact {
        Jwe::parse(wire)
    } else {
        Jwe::parse_json(wire.as_bytes())
    }
}

#[test]
fn section_5() {
    let tally = run::<Case>(vector!("rfc7520/jwe-cases.json"), 1, |case| {
        let owned = common_jwe::LOCAL.contains(&case.alg.as_str());
        let refused = ["RSA1_5", "PBES2-HS512+A256KW"].contains(&case.alg.as_str());
        if !owned && !refused {
            return Outcome::NotApplicable;
        }
        let jwk = case.jwk.as_ref().map_or("{}", Json::text);
        let compact = case.serialization == "compact";
        let wire = if compact {
            case.jwe.parse::<String>()
        } else {
            case.jwe.text().to_owned()
        };
        if refused {
            for alg in common_jwe::LOCAL {
                let outcome = parse(compact, &wire)
                    .and_then(|jwe| common_jwe::decrypt(alg, &case.enc, jwk, jwe));
                common_refusal::assert_outcome(&outcome, false, None, &case.id);
            }
            assert_eq!(
                JweAlg::parse(&case.alg).err().map(|e| e.kind()),
                Some(ErrorKind::UnsupportedAlg)
            );
            return Outcome::Checked;
        }
        let outcome = parse(compact, &wire)
            .and_then(|jwe| common_jwe::decrypt(&case.alg, &case.enc, jwk, jwe));
        common_refusal::assert_outcome(&outcome, case.expect.ok, None, &case.id);
        if let Some(want) = &case.expect.plaintext {
            let got = outcome.ok().map(|plaintext| b64url_encode(&plaintext));
            assert_eq!(got.as_ref(), Some(want), "{}", case.id);
        }
        Outcome::Checked
    });
    assert_eq!(tally.total(), 64);
    assert!(tally.checked() > 30, "{}", tally.checked());
}
