//! The oracle's `origins.json` through `Origin::parse` and `RpId::parse`.
use serde::Deserialize;
use testkit::vectors::{Outcome, run};
use webauthn_rp::{Origin, RpId};

use crate::refusal::Refusal;

#[derive(Deserialize)]
struct Expect {
    ok: bool,
    #[serde(flatten)]
    refusal: Refusal,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    op: String,
    input: String,
    unbuilt: Option<String>,
    expect: Expect,
}

pub(crate) fn cases() {
    let tally = run::<Case>(
        testkit::vector!("webauthn-rp-derived/origins.json"),
        78,
        |c| {
            let parsed = match c.op.as_str() {
                "origin_parse" => Origin::parse(&c.input).map(|o| o.as_str().to_owned()),
                "rp_id_parse" => RpId::parse(&c.input).map(|r| r.as_str().to_owned()),
                "app_id_parse" => {
                    assert!(c.unbuilt.is_some(), "{}: AppId::parse is unbuilt", c.id);
                    return Outcome::NotApplicable;
                }
                _ => return Outcome::NotApplicable,
            };
            assert!(c.unbuilt.is_none(), "{}: marked unbuilt, yet read", c.id);
            match parsed {
                Ok(text) => {
                    assert!(c.expect.ok, "{}: accepted", c.id);
                    assert_eq!(text, c.input, "{}: kept as written", c.id);
                }
                Err(err) => {
                    assert!(!c.expect.ok, "{}: refused as {:?}", c.id, err.kind());
                    c.expect
                        .refusal
                        .check(&c.id, None, err.kind(), err.spec_step());
                }
            }
            Outcome::Checked
        },
    );
    assert_eq!((tally.total(), tally.checked()), (90, 78));
}
