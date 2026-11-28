//! The JWS JSON serializations, general and flattened (RFC 7515 section 7.2), and writing them from compact tokens.
use alloc::string::String;
use alloc::vec::Vec;

use base::b64url_decode;
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::json::{Capped, Object, named, object, scan};
use crate::jws::compact::Signature;
use crate::jws::header::Parsed;
use crate::{Compact, Error, ErrorKind, Jws, MAX_ENTRIES};

#[derive(Deserialize)]
struct Entry<'a> {
    #[serde(default, deserialize_with = "named")]
    protected: Option<&'a str>,
    #[serde(default, deserialize_with = "named")]
    header: Option<&'a RawValue>,
    signature: &'a str,
}

//= https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1
//# payload The "payload" member MUST be present and contain the value BASE64URL(JWS Payload).
//= https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1
//# signatures The "signatures" member value MUST be an array of JSON objects.
//= https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1
//# signature The "signature" member MUST be present and contain the value BASE64URL(JWS Signature).
//= https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1
//# Additional members can be present in both the JSON objects defined above; if not understood by
//# implementations encountering them, they MUST be ignored.
#[derive(Deserialize)]
struct Document<'a> {
    payload: &'a str,
    #[serde(default, deserialize_with = "named")]
    protected: Option<&'a str>,
    #[serde(default, deserialize_with = "named")]
    header: Option<&'a RawValue>,
    #[serde(default, deserialize_with = "named")]
    signature: Option<&'a str>,
    #[serde(default, deserialize_with = "named")]
    signatures: Option<Capped<Object<Entry<'a>>>>,
}

impl<'a> Jws<'a> {
    /// Parses the general (`signatures`) or flattened (`protected`, `header`, `signature`) JSON serialization; a
    /// name used twice, in one object or across a signature's protected and unprotected headers, is `DuplicateMember`,
    /// and more than `MAX_ENTRIES` signatures is `TooLarge`.
    pub fn parse_json(json: &'a [u8]) -> Result<Self, Error> {
        scan(json)?;
        let document: Document<'a> = object(json).map_err(|_| ErrorKind::Malformed)?;
        //= https://www.rfc-editor.org/rfc/rfc7515#section-7.2.2
        //# The "signatures" member MUST NOT be present when using this syntax.
        let entries = match (document.signatures, document.signature) {
            (Some(entries), None) if document.protected.is_none() && document.header.is_none() => {
                entries.0.into_iter().map(|Object(entry)| entry).collect()
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
        let sole = entries.len() == 1;
        let mut signatures = Vec::new();
        for entry in entries {
            let protected = entry.protected.unwrap_or_default();
            let header = Parsed::parse(protected, entry.header.map(|h| h.get()))?;
            if sole {
                header.supported()?;
            }
            signatures.push(Signature {
                protected,
                header,
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
    //= https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1
    //# encrypted_key The "encrypted_key" member MUST be present and contain the value BASE64URL(JWE
    //# Encrypted Key) when the JWE Encrypted Key value is non-empty; otherwise, it MUST be absent.
    //= https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1
    //= type=exception
    //= reason=a JWE that jose serializes never carries this member (it writes only protected, encrypted_key, iv, ciphertext and tag), so there is no value to present or omit
    //# header The "header" member MUST be present and contain the value JWE Per-Recipient
    //# Unprotected Header when the JWE Per-Recipient Unprotected Header value is non-empty;
    //# otherwise, it MUST be absent.
    //= https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1
    //# tag The "tag" member MUST be present and contain the value BASE64URL(JWE Authentication Tag)
    //# when the JWE Authentication Tag value is non-empty; otherwise, it MUST be absent.
    //= https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1
    //# ciphertext The "ciphertext" member MUST be present and contain the value BASE64URL(JWE
    //# Ciphertext).
    //= https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1
    //= type=exception
    //= reason=a JWE that jose serializes never carries this member (it writes only protected, encrypted_key, iv, ciphertext and tag), so there is no value to present or omit
    //# aad The "aad" member MUST be present and contain the value BASE64URL(JWE AAD)) when the JWE
    //# AAD value is non-empty; otherwise, it MUST be absent.
    //= https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1
    //# iv The "iv" member MUST be present and contain the value BASE64URL(JWE Initialization
    //# Vector) when the JWE Initialization Vector value is non-empty; otherwise, it MUST be absent.
    //= https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1
    //= type=exception
    //= reason=a JWE that jose serializes never carries this member (it writes only protected, encrypted_key, iv, ciphertext and tag), so there is no value to present or omit
    //# unprotected The "unprotected" member MUST be present and contain the value JWE Shared
    //# Unprotected Header when the JWE Shared Unprotected Header value is non-empty; otherwise, it
    //# MUST be absent.
    //= https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1
    //# protected The "protected" member MUST be present and contain the value BASE64URL(UTF8(JWE
    //# Protected Header)) when the JWE Protected Header value is non-empty; otherwise, it MUST be
    //# absent.
    //= https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1
    //# protected The "protected" member MUST be present and contain the value BASE64URL(UTF8(JWS
    //# Protected Header)) when the JWS Protected Header value is non-empty; otherwise, it MUST be
    //# absent.
    //= https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1
    //# header The "header" member MUST be present and contain the value JWS Unprotected Header when
    //# the JWS Unprotected Header value is non-empty; otherwise, it MUST be absent.
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

    //= https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1
    //= type=exception
    //= reason=jose produces no general JWE serialization, so no recipients member is written; non-goal N10
    //# This member MUST be present with exactly one array element per recipient, even if some or
    //# all of the array element values are the empty JSON object "{}" (which can happen when all
    //# Header Parameter values are shared between all recipients and when no encrypted key is used,
    //# such as when doing Direct Encryption).
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
    fn an_alg_behind_an_off_feature_skips_one_entry_not_the_token() {
        let es512 = base::b64url_encode(br#"{"alg":"ES512"}"#);
        let entry = |protected: &str| format!(r#"{{"protected":"{protected}","signature":"AQ"}}"#);
        let general = |entries: &[String]| {
            format!(r#"{{"payload":"AA","signatures":[{}]}}"#, entries.join(","))
        };
        assert_eq!(kind(&general(&[entry(&es512), entry(H)])), None);
        let sole = general(&[entry(&es512)]);
        let off = cfg!(not(feature = "es512"));
        assert_eq!(kind(&sole), off.then_some(ErrorKind::UnsupportedAlg));
    }

    #[test]
    fn a_null_member_is_malformed_not_absent() {
        let sig = |extra: &str| format!(r#"{{"protected":"{H}"{extra},"signature":"AQ"}}"#);
        let flat = |extra: &str| {
            format!(r#"{{"payload":"AA","protected":"{H}"{extra},"signature":"AQ"}}"#)
        };
        let general = |entry: &str, extra: &str| {
            format!(r#"{{"payload":"AA"{extra},"signatures":[{entry}]}}"#)
        };
        // positive controls: the shapes with the member omitted or holding a value
        assert_eq!(kind(&flat("")), None);
        assert_eq!(kind(&flat(r#","header":{"kid":"k"}"#)), None);
        assert_eq!(kind(&general(&sig(""), "")), None);
        let nulls = [
            flat(r#","header":null"#),
            r#"{"payload":"AA","protected":null,"header":{"alg":"HS256"},"signature":"AQ"}"#
                .to_string(),
            format!(r#"{{"payload":"AA","protected":"{H}","signature":null}}"#),
            format!(r#"{{"payload":null,"protected":"{H}","signature":"AQ"}}"#),
            format!(r#"{{"payload":"AA","signatures":null,"protected":"{H}","signature":"AQ"}}"#),
            general(&sig(r#","header":null"#), ""),
            general(
                r#"{"protected":null,"header":{"alg":"HS256"},"signature":"AQ"}"#,
                "",
            ),
            general(&format!(r#"{{"protected":"{H}","signature":null}}"#), ""),
        ];
        for json in nulls {
            assert_eq!(kind(&json), Some(ErrorKind::Malformed), "{json}");
        }
        // a header member of null (RFC 7515 4.1.4 types kid, typ and cty as strings), in the protected and the
        // unprotected header; alg is carried in the other one, so only the null can make the document Malformed
        let doc = |protected: &str, header: &str| {
            let protected = base::b64url_encode(protected.as_bytes());
            format!(
                r#"{{"payload":"AA","protected":"{protected}","header":{header},"signature":"AQ"}}"#
            )
        };
        assert_eq!(kind(&doc(r#"{}"#, r#"{"alg":"HS256"}"#)), None);
        for name in ["kid", "typ", "cty"] {
            let own = format!(r#"{{"alg":"HS256","{name}":"x"}}"#);
            let hdr = format!(r#"{{"{name}":"x"}}"#);
            assert_eq!(kind(&doc(&own, "{}")), None, "{name} string, protected");
            assert_eq!(
                kind(&doc(r#"{"alg":"HS256"}"#, &hdr)),
                None,
                "{name} string, header"
            );
            let own = format!(r#"{{"alg":"HS256","{name}":null}}"#);
            let hdr = format!(r#"{{"{name}":null}}"#);
            assert_eq!(kind(&doc(&own, "{}")), Some(ErrorKind::Malformed), "{name}");
            assert_eq!(
                kind(&doc(r#"{"alg":"HS256"}"#, &hdr)),
                Some(ErrorKind::Malformed),
                "{name} header"
            );
        }
        // alg: the same name in the other header would be DuplicateMember were null read as absent
        assert_eq!(
            kind(&doc(r#"{"alg":null}"#, r#"{"alg":"HS256"}"#)),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            kind(&doc(r#"{"alg":"HS256"}"#, r#"{"alg":null}"#)),
            Some(ErrorKind::Malformed)
        );
    }

    #[test]
    fn a_document_or_entry_written_as_an_array_is_malformed() {
        // serde reads a struct from an array by position: payload, protected, header, signature, signatures
        assert_eq!(
            kind(&format!(r#"["AA","{H}",null,"AQ"]"#)),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            kind(&format!(r#"["AA","{H}",{{"kid":"k"}},"AQ"]"#)),
            Some(ErrorKind::Malformed)
        );
        // an entry: protected, header, signature
        let entry = format!(r#"["{H}",{{"kid":"k"}},"AQ"]"#);
        assert_eq!(
            kind(&format!(r#"{{"payload":"AA","signatures":[{entry}]}}"#)),
            Some(ErrorKind::Malformed)
        );
        let object = format!(r#"{{"protected":"{H}","header":{{"kid":"k"}},"signature":"AQ"}}"#);
        assert_eq!(
            kind(&format!(r#"{{"payload":"AA","signatures":[{object}]}}"#)),
            None
        );
    }

    //= https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1
    //= type=test
    //# Additional members can be present in both the JSON objects defined above; if not understood
    //# by implementations encountering them, they MUST be ignored.
    #[test]
    fn signatures_beside_flattened_members_are_malformed() {
        let sig = format!(r#"{{"protected":"{H}","signature":"AQ"}}"#);
        let with = |extra: &str| format!(r#"{{"payload":"AA",{extra},"signatures":[{sig}]}}"#);
        assert_eq!(
            kind(&with(&format!(r#""protected":"{H}""#))),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            kind(&with(r#""header":{"kid":"k"}"#)),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(kind(&with(r#""x":1"#)), None);
    }

    //= https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1
    //= type=test
    //# encrypted_key The "encrypted_key" member MUST be present and contain the value BASE64URL(JWE
    //# Encrypted Key) when the JWE Encrypted Key value is non-empty; otherwise, it MUST be absent.
    //= https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1
    //= type=test
    //# tag The "tag" member MUST be present and contain the value BASE64URL(JWE Authentication Tag)
    //# when the JWE Authentication Tag value is non-empty; otherwise, it MUST be absent.
    //= https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1
    //= type=test
    //# ciphertext The "ciphertext" member MUST be present and contain the value BASE64URL(JWE
    //# Ciphertext).
    //= https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1
    //= type=test
    //# iv The "iv" member MUST be present and contain the value BASE64URL(JWE Initialization
    //# Vector) when the JWE Initialization Vector value is non-empty; otherwise, it MUST be absent.
    //= https://www.rfc-editor.org/rfc/rfc7516#section-7.2.1
    //= type=test
    //# protected The "protected" member MUST be present and contain the value BASE64URL(UTF8(JWE
    //# Protected Header)) when the JWE Protected Header value is non-empty; otherwise, it MUST be
    //# absent.
    //= https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1
    //= type=test
    //# protected The "protected" member MUST be present and contain the value BASE64URL(UTF8(JWS
    //# Protected Header)) when the JWS Protected Header value is non-empty; otherwise, it MUST be
    //# absent.
    //= https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1
    //= type=test
    //# header The "header" member MUST be present and contain the value JWS Unprotected Header when
    //# the JWS Unprotected Header value is non-empty; otherwise, it MUST be absent.
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

    //= https://www.rfc-editor.org/rfc/rfc7515#section-5.2
    //= type=test
    //# When using the JWS JSON Serialization, this restriction includes that the same Header
    //# Parameter name also MUST NOT occur in distinct JSON object values that together comprise the
    //# JOSE Header.
    //= https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1
    //= type=test
    //# The Header Parameter names in the two locations MUST be disjoint.
    //= https://www.rfc-editor.org/rfc/rfc7515#section-4.1.11
    //= type=test
    //# When used, this Header Parameter MUST be integrity protected; therefore, it MUST occur only
    //# within the JWS Protected Header.
    //= https://www.rfc-editor.org/rfc/rfc7515#section-7.2.2
    //= type=test
    //# The "signatures" member MUST NOT be present when using this syntax.
    //= https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1
    //= type=test
    //# signature The "signature" member MUST be present and contain the value BASE64URL(JWS
    //# Signature).
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
