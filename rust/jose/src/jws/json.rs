//! The JWS JSON serializations, general and flattened (RFC 7515 section 7.2), and writing them from compact tokens.
use alloc::string::String;
use alloc::vec::Vec;

use base::b64url_decode;
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::jwk::decode::scan;
use crate::jws::compact::Signature;
use crate::jws::header::Parsed;
use crate::{Compact, Error, ErrorKind, Jws, MAX_ENTRIES};

#[derive(Deserialize)]
struct Entry<'a> {
    protected: Option<&'a str>,
    header: Option<&'a RawValue>,
    signature: &'a str,
}

#[derive(Deserialize)]
struct Document<'a> {
    payload: &'a str,
    protected: Option<&'a str>,
    header: Option<&'a RawValue>,
    signature: Option<&'a str>,
    signatures: Option<Vec<Entry<'a>>>,
}

impl<'a> Jws<'a> {
    /// Parses the general (`signatures`) or flattened (`protected`, `header`, `signature`) JSON serialization; a
    /// name used twice, in one object or across a signature's protected and unprotected headers, is `DuplicateMember`,
    /// and more than `MAX_ENTRIES` signatures is `TooLarge`.
    pub fn parse_json(json: &'a [u8]) -> Result<Self, Error> {
        scan(json)?;
        let document: Document<'a> =
            serde_json::from_slice(json).map_err(|_| ErrorKind::Malformed)?;
        let entries = match (document.signatures, document.signature) {
            (Some(entries), None) if document.protected.is_none() && document.header.is_none() => {
                entries
            }
            (None, Some(signature)) => alloc::vec![Entry {
                protected: document.protected,
                header: document.header,
                signature,
            }],
            _ => return Err(ErrorKind::Malformed.into()),
        };
        if entries.len() > MAX_ENTRIES {
            return Err(ErrorKind::TooLarge.into());
        }
        if entries.is_empty() {
            return Err(ErrorKind::Malformed.into());
        }
        b64url_decode(document.payload).map_err(|_| ErrorKind::Malformed)?;
        let mut signatures = Vec::new();
        for entry in entries {
            let protected = entry.protected.unwrap_or_default();
            signatures.push(Signature {
                protected,
                header: Parsed::parse(protected, entry.header.map(|h| h.get()))?,
                bytes: b64url_decode(entry.signature).map_err(|_| ErrorKind::Malformed)?,
            });
        }
        Ok(Self {
            payload: document.payload,
            kids: signatures
                .iter()
                .filter_map(|s| s.header.kid.clone())
                .collect(),
            signatures,
        })
    }
}

impl Compact {
    /// The flattened JSON serialization of this token: a JWS as `payload`, `protected`, `signature`; a JWE as
    /// `protected`, `encrypted_key` (when not empty), `iv`, `ciphertext`, `tag`.
    pub fn flattened(&self) -> String {
        let parts: Vec<&str> = self.0.split('.').collect();
        match parts.as_slice() {
            [protected, payload, signature] => alloc::format!(
                r#"{{"payload":"{payload}","protected":"{protected}","signature":"{signature}"}}"#
            ),
            [protected, key, iv, ciphertext, tag] => {
                let key = if key.is_empty() {
                    String::new()
                } else {
                    alloc::format!(r#""encrypted_key":"{key}","#)
                };
                alloc::format!(
                    r#"{{"protected":"{protected}",{key}"iv":"{iv}","ciphertext":"{ciphertext}","tag":"{tag}"}}"#
                )
            }
            _ => String::new(),
        }
    }

    /// The general JSON serialization of JWS tokens over one payload; different payloads or a JWE are `Malformed`,
    /// and more than `MAX_ENTRIES` tokens `TooLarge`.
    pub fn general(tokens: &[Compact]) -> Result<String, Error> {
        if tokens.len() > MAX_ENTRIES {
            return Err(ErrorKind::TooLarge.into());
        }
        let mut payload = None;
        let mut signatures = Vec::new();
        for token in tokens {
            let parts: Vec<&str> = token.0.split('.').collect();
            let [protected, body, signature] = parts.as_slice() else {
                return Err(ErrorKind::Malformed.into());
            };
            if *payload.get_or_insert(*body) != *body {
                return Err(ErrorKind::Malformed.into());
            }
            signatures.push(alloc::format!(
                r#"{{"protected":"{protected}","signature":"{signature}"}}"#
            ));
        }
        let payload = payload.ok_or(ErrorKind::Malformed)?;
        Ok(alloc::format!(
            r#"{{"payload":"{payload}","signatures":[{}]}}"#,
            signatures.join(",")
        ))
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::{String, ToString as _};
    use alloc::vec::Vec;

    use super::Jws;
    use crate::{Compact, ErrorKind, MAX_ENTRIES};

    const H: &str = "eyJhbGciOiJIUzI1NiJ9";

    fn kind(json: &str) -> Option<ErrorKind> {
        Jws::parse_json(json.as_bytes()).err().map(|e| e.kind())
    }

    fn token(protected: &str, payload: &str, signature: &str) -> Compact {
        Compact(format!("{protected}.{payload}.{signature}"))
    }

    #[test]
    fn serializations() {
        let one = token(H, "AA", "AQ");
        assert_eq!(
            one.flattened(),
            format!(r#"{{"payload":"AA","protected":"{H}","signature":"AQ"}}"#)
        );
        let two = token(H, "AA", "Ag");
        let general = Compact::general(&[one.clone(), two]);
        let want = format!(
            r#"{{"payload":"AA","signatures":[{{"protected":"{H}","signature":"AQ"}},{{"protected":"{H}","signature":"Ag"}}]}}"#
        );
        assert_eq!(general.ok(), Some(want));
        let jwe = Compact("a..b.c.d".to_string());
        assert_eq!(
            jwe.flattened(),
            r#"{"protected":"a","iv":"b","ciphertext":"c","tag":"d"}"#
        );
        let jwe = Compact("a.k.b.c.d".to_string());
        assert_eq!(
            jwe.flattened(),
            r#"{"protected":"a","encrypted_key":"k","iv":"b","ciphertext":"c","tag":"d"}"#
        );
        assert_eq!(Compact("a.b".to_string()).flattened(), "");
        let kinds = |tokens: &[Compact]| Compact::general(tokens).err().map(|e| e.kind());
        assert_eq!(
            kinds(&[one.clone(), token(H, "BB", "AQ")]),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            kinds(&[one.clone(), Compact("a.b.c.d.e".to_string())]),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(kinds(&[]), Some(ErrorKind::Malformed));
        let many: Vec<Compact> = (0..=MAX_ENTRIES).map(|_| one.clone()).collect();
        assert_eq!(kinds(many.get(..MAX_ENTRIES).unwrap_or_default()), None);
        assert_eq!(kinds(&many), Some(ErrorKind::TooLarge));
    }

    #[test]
    fn parsing() {
        let entry = format!(r#"{{"protected":"{H}","signature":"AQ"}}"#);
        let general = |n: usize| {
            let entries: Vec<String> = (0..n).map(|_| entry.clone()).collect();
            format!(r#"{{"payload":"AA","signatures":[{}]}}"#, entries.join(","))
        };
        assert_eq!(kind(&general(MAX_ENTRIES)), None);
        assert_eq!(kind(&general(MAX_ENTRIES + 1)), Some(ErrorKind::TooLarge));
        assert_eq!(kind(&general(0)), Some(ErrorKind::Malformed));
        let flat = format!(r#"{{"payload":"AA","protected":"{H}","signature":"AQ"}}"#);
        assert_eq!(kind(&flat), None);
        let both = format!(
            r#"{{"payload":"AA","protected":"{H}","signature":"AQ","signatures":[{entry}]}}"#
        );
        assert_eq!(kind(&both), Some(ErrorKind::Malformed));
        let mixed = format!(r#"{{"payload":"AA","protected":"{H}","signatures":[{entry}]}}"#);
        assert_eq!(kind(&mixed), Some(ErrorKind::Malformed));
        let headed = format!(r#"{{"payload":"AA","header":{{"x":1}},"signatures":[{entry}]}}"#);
        assert_eq!(kind(&headed), Some(ErrorKind::Malformed));
        assert_eq!(kind(r#"{"payload":"AA"}"#), Some(ErrorKind::Malformed));
        assert_eq!(
            kind(&flat.replace("\"AA\"", "\"A\"")),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            kind(&flat.replace("\"AQ\"", "\"A=\"")),
            Some(ErrorKind::Malformed)
        );
        let repeated =
            format!(r#"{{"payload":"AA","protected":"{H}","signature":"AQ","signature":"AQ"}}"#);
        assert_eq!(kind(&repeated), Some(ErrorKind::DuplicateMember));
        let unprotected = r#"{"payload":"AA","header":{"alg":"HS256"},"signature":"AQ"}"#;
        assert_eq!(kind(unprotected), None);
        let clash = format!(
            r#"{{"payload":"AA","protected":"{H}","header":{{"alg":"HS256"}},"signature":"AQ"}}"#
        );
        assert_eq!(kind(&clash), Some(ErrorKind::DuplicateMember));
        let hinted = format!(
            r#"{{"payload":"AA","protected":"{H}","header":{{"kid":"k"}},"signature":"AQ"}}"#
        );
        let jws = Jws::parse_json(hinted.as_bytes()).ok();
        assert_eq!(jws.map(|j| j.kids().len()), Some(1));
        let crit = format!(
            r#"{{"payload":"AA","protected":"{H}","header":{{"crit":["x"],"x":1}},"signature":"AQ"}}"#
        );
        assert_eq!(kind(&crit), Some(ErrorKind::Malformed));
    }
}
