//! The oracle's CBOR cases through the strict reader and the COSE parser.
use serde::Deserialize;
use testkit::vector;
use testkit::vectors::{Outcome, run};

use crate::cbor::{Order, decode};
use crate::cose::CoseKey;
use crate::hex::hex;
use crate::refusal::Refusal;
use crate::{MAX_CBOR_DEPTH, MAX_CBOR_ITEMS};

#[derive(Deserialize)]
struct Case {
    id: String,
    #[serde(default, deserialize_with = "hex")]
    input: Vec<u8>,
    bound: Option<String>,
    expect: Expect,
}

#[derive(Deserialize)]
struct Expect {
    ok: bool,
    #[serde(flatten)]
    refusal: Refusal,
}

// the bound plus one: nested arrays, or one array of zeros
fn past(bound: &str) -> Vec<u8> {
    match bound {
        "webauthn_rp::MAX_CBOR_DEPTH" => [vec![0x81; MAX_CBOR_DEPTH + 1], vec![0]].concat(),
        "webauthn_rp::MAX_CBOR_ITEMS" => [vec![0x99, 0x04, 0x00], vec![0; MAX_CBOR_ITEMS]].concat(),
        _ => Vec::new(),
    }
}

pub(crate) fn cases() {
    let tally = run::<Case>(vector!("webauthn-rp-derived/cbor.json"), 21, |c| {
        let bytes = c.bound.as_deref().map_or_else(|| c.input.clone(), past);
        let decoded = decode(&bytes, Order::Canonical);
        assert_eq!(decoded.is_ok(), c.expect.ok, "{}", c.id);
        if let Err(err) = &decoded {
            c.expect
                .refusal
                .check(&c.id, None, err.kind(), err.spec_step());
        }
        if let (Ok(value), "cose-key-canonical") = (&decoded, c.id.as_str()) {
            assert!(matches!(CoseKey::parse(value), Ok(CoseKey::Es256 { .. })));
        }
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (21, 21));
}
