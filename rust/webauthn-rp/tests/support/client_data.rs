//! The oracle's clientDataJSON cases through the bounded reader, `Origin` and `RpId`.
use serde::Deserialize;
use testkit::vector;
use testkit::vectors::{Outcome, run};
use webauthn_rp::{Origin, RpId};

use crate::client_data::ClientData;
use crate::error::ErrorKind;
use crate::hex::hex;
use crate::{MAX_CLIENT_DATA_DEPTH, MAX_CLIENT_DATA_JSON};

#[derive(Deserialize)]
struct Case {
    id: String,
    #[serde(deserialize_with = "hex")]
    client_data_json: Vec<u8>,
    rp_id: String,
    origin: String,
    challenge: String,
}

// the members the reader reads, typed independently of it
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Members {
    r#type: Option<String>,
    origin: Option<String>,
    top_origin: Option<String>,
    cross_origin: Option<bool>,
}

pub(crate) fn cases() {
    let tally = run::<Case>(vector!("webauthn-rp-derived/client-data.json"), 20, |c| {
        let parsed = ClientData::parse(&c.client_data_json);
        if c.id == "client-data-not-json" {
            assert_eq!(parsed.err().map(|e| e.kind()), Some(ErrorKind::Malformed));
            return Outcome::Checked;
        }
        assert_eq!(parsed.as_ref().err(), None, "{}", c.id);
        let Ok(data) = parsed else {
            return Outcome::NotApplicable;
        };
        let json = serde_json::from_slice::<Members>(&c.client_data_json);
        assert_eq!(
            json.as_ref().err().map(ToString::to_string),
            None,
            "{}",
            c.id
        );
        let Ok(json) = json else {
            return Outcome::NotApplicable;
        };
        assert_eq!(
            Some(data.kind.as_str()),
            json.r#type.as_deref().or(Some("")),
            "{}",
            c.id
        );
        assert_eq!(
            Some(data.origin.as_str()),
            json.origin.as_deref().or(Some("")),
            "{}",
            c.id
        );
        assert_eq!(data.top_origin, json.top_origin, "{}", c.id);
        assert_eq!(data.cross_origin, json.cross_origin, "{}", c.id);
        let own = base::b64url_decode(&c.challenge).ok();
        match c.id.as_str() {
            "challenge-padded" | "challenge-std-alphabet" | "challenge-missing" => {
                assert!(data.challenge.is_empty())
            }
            "challenge-other" => {
                assert!(data.challenge.len() == 32 && Some(&data.challenge) != own.as_ref())
            }
            _ => assert_eq!(Some(&data.challenge), own.as_ref(), "{}", c.id),
        }
        let origin = Origin::parse(&data.origin);
        assert_eq!(
            origin.is_ok(),
            !matches!(c.id.as_str(), "origin-trailing-slash" | "origin-http"),
            "{}",
            c.id
        );
        let same = origin.is_ok_and(|o| o.as_str() == c.origin);
        assert_eq!(
            same,
            !matches!(
                c.id.as_str(),
                "origin-other"
                    | "origin-port"
                    | "origin-subdomain"
                    | "origin-trailing-slash"
                    | "origin-http"
            )
        );
        assert!(RpId::parse(&c.rp_id).is_ok());
        Outcome::Checked
    });
    assert_eq!((tally.total(), tally.checked()), (20, 20));
}

pub(crate) fn bounds() {
    let padded = |len: usize| [b"{}".to_vec(), vec![b' '; len - 2]].concat();
    assert!(ClientData::parse(&padded(MAX_CLIENT_DATA_JSON)).is_ok());
    let past = ClientData::parse(&padded(MAX_CLIENT_DATA_JSON + 1));
    assert_eq!(past.err().map(|e| e.kind()), Some(ErrorKind::TooLarge));
    let nested = |depth: usize| format!(r#"{{"a":{}0{}}}"#, "[".repeat(depth), "]".repeat(depth));
    assert!(ClientData::parse(nested(MAX_CLIENT_DATA_DEPTH - 1).as_bytes()).is_ok());
    let deep = ClientData::parse(nested(MAX_CLIENT_DATA_DEPTH).as_bytes());
    assert_eq!(deep.err().map(|e| e.kind()), Some(ErrorKind::TooLarge));
}
