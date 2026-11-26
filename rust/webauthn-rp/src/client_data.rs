//! The bounded clientDataJSON reader (R6, R7).
#![cfg_attr(
    not(test),
    expect(dead_code, reason = "read by the ceremonies, webauthn-04")
)]
use alloc::string::String;
use alloc::vec::Vec;
use core::str;

use crate::error::{Error, ErrorKind};
use crate::{MAX_CLIENT_DATA_DEPTH, MAX_CLIENT_DATA_JSON};

/// The members of `clientDataJSON` the ceremonies check; the steps compare them, the reader only reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClientData {
    /// `type`, as sent.
    pub(crate) kind: String,
    /// `challenge` decoded; empty when it is not canonical base64url, so no ceremony matches (R7).
    pub(crate) challenge: Vec<u8>,
    /// `origin`, as sent.
    pub(crate) origin: String,
    /// `crossOrigin`, when present.
    pub(crate) cross_origin: Option<bool>,
    /// `topOrigin`, when present.
    pub(crate) top_origin: Option<String>,
}

impl ClientData {
    /// Reads one JSON object; members the ceremonies do not check are skipped, a checked member of the wrong type is `Malformed`.
    pub(crate) fn parse(json: &[u8]) -> Result<Self, Error> {
        if json.len() > MAX_CLIENT_DATA_JSON {
            return Err(Error::new(ErrorKind::TooLarge));
        }
        let text = str::from_utf8(json).map_err(|_| malformed())?;
        let mut reader = Reader {
            rest: text.strip_prefix('\u{feff}').unwrap_or(text),
        };
        reader.space();
        reader.expect('{')?;
        let members = reader.object(1)?;
        reader.space();
        if !reader.rest.is_empty() {
            return Err(malformed());
        }
        let text = |name: &str| match members.iter().find(|(n, _)| n == name) {
            None => Ok(None),
            Some((_, Json::Text(t))) => Ok(Some(t.clone())),
            Some(_) => Err(malformed()),
        };
        let cross_origin = match members.iter().find(|(n, _)| n == "crossOrigin") {
            None => None,
            Some((_, Json::Bool(b))) => Some(*b),
            Some(_) => return Err(malformed()),
        };
        let challenge = text("challenge")?
            .and_then(|c| base::b64url_decode(&c).ok())
            .filter(|c| c.len() == 32)
            .unwrap_or_default();
        Ok(Self {
            kind: text("type")?.unwrap_or_default(),
            challenge,
            origin: text("origin")?.unwrap_or_default(),
            cross_origin,
            top_origin: text("topOrigin")?,
        })
    }
}

const fn malformed() -> Error {
    Error::new(ErrorKind::Malformed)
}

enum Json {
    Text(String),
    Bool(bool),
    Other,
}

struct Reader<'a> {
    rest: &'a str,
}

impl Reader<'_> {
    fn eat(&mut self, c: char) -> bool {
        self.rest
            .strip_prefix(c)
            .inspect(|r| self.rest = r)
            .is_some()
    }

    fn expect(&mut self, c: char) -> Result<(), Error> {
        if self.eat(c) {
            Ok(())
        } else {
            Err(malformed())
        }
    }

    fn word(&mut self, word: &str) -> bool {
        self.rest
            .strip_prefix(word)
            .inspect(|r| self.rest = r)
            .is_some()
    }

    fn space(&mut self) {
        self.rest = self.rest.trim_start_matches([' ', '\t', '\n', '\r']);
    }

    fn digits(&mut self) -> Result<(), Error> {
        let rest = self.rest.trim_start_matches(|c: char| c.is_ascii_digit());
        if rest.len() == self.rest.len() {
            return Err(malformed());
        }
        self.rest = rest;
        Ok(())
    }

    fn number(&mut self) -> Result<(), Error> {
        self.eat('-');
        if !self.eat('0') {
            self.digits()?;
        }
        if self.eat('.') {
            self.digits()?;
        }
        if self.eat('e') || self.eat('E') {
            let _ = self.eat('+') || self.eat('-');
            self.digits()?;
        }
        Ok(())
    }

    fn next(&mut self) -> Result<char, Error> {
        let c = self.rest.chars().next().ok_or_else(malformed)?;
        self.rest = self.rest.get(c.len_utf8()..).ok_or_else(malformed)?;
        Ok(c)
    }

    fn unit(&mut self) -> Result<u32, Error> {
        let hex = self
            .rest
            .get(..4)
            .filter(|h| h.bytes().all(|b| b.is_ascii_hexdigit()));
        let unit = hex
            .and_then(|h| u32::from_str_radix(h, 16).ok())
            .ok_or_else(malformed)?;
        self.rest = self.rest.get(4..).ok_or_else(malformed)?;
        Ok(unit)
    }

    // after the opening quote
    fn string(&mut self) -> Result<String, Error> {
        let mut out = String::new();
        loop {
            out.push(match self.next()? {
                '"' => return Ok(out),
                '\\' => self.escape()?,
                c if c >= ' ' => c,
                _ => return Err(malformed()),
            });
        }
    }

    fn escape(&mut self) -> Result<char, Error> {
        let c = match self.next()? {
            c @ ('"' | '\\' | '/') => c,
            'b' => '\u{8}',
            'f' => '\u{c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'u' => match self.unit()? {
                high @ 0xd800..=0xdbff => {
                    if !self.word("\\u") {
                        return Err(malformed());
                    }
                    let low = self.unit()?;
                    if !(0xdc00..=0xdfff).contains(&low) {
                        return Err(malformed());
                    }
                    char::from_u32(0x1_0000 + ((high - 0xd800) << 10) + (low - 0xdc00))
                }
                unit => char::from_u32(unit),
            }
            .ok_or_else(malformed)?,
            _ => return Err(malformed()),
        };
        Ok(c)
    }

    // `depth` is the depth of the object or array holding the value
    fn value(&mut self, depth: usize) -> Result<Json, Error> {
        self.space();
        if self.rest.starts_with(['{', '[']) && depth >= MAX_CLIENT_DATA_DEPTH {
            return Err(Error::new(ErrorKind::TooLarge));
        }
        if self.eat('"') {
            self.string().map(Json::Text)
        } else if self.eat('{') {
            self.object(depth + 1).map(|_| Json::Other)
        } else if self.eat('[') {
            self.array(depth + 1).map(|()| Json::Other)
        } else if self.word("true") {
            Ok(Json::Bool(true))
        } else if self.word("false") {
            Ok(Json::Bool(false))
        } else if self.word("null") {
            Ok(Json::Other)
        } else {
            self.number().map(|()| Json::Other)
        }
    }

    // after the opening brace
    fn object(&mut self, depth: usize) -> Result<Vec<(String, Json)>, Error> {
        let mut members: Vec<(String, Json)> = Vec::new();
        self.space();
        if self.eat('}') {
            return Ok(members);
        }
        loop {
            self.space();
            self.expect('"')?;
            let name = self.string()?;
            if members.iter().any(|(n, _)| *n == name) {
                return Err(malformed());
            }
            self.space();
            self.expect(':')?;
            members.push((name, self.value(depth)?));
            self.space();
            if !self.eat(',') {
                return self.expect('}').map(|()| members);
            }
        }
    }

    // after the opening bracket
    fn array(&mut self, depth: usize) -> Result<(), Error> {
        self.space();
        if self.eat(']') {
            return Ok(());
        }
        loop {
            self.value(depth)?;
            self.space();
            if !self.eat(',') {
                return self.expect(']');
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::ToString;
    use alloc::vec;

    use super::ClientData;
    use crate::error::ErrorKind;
    use crate::{MAX_CLIENT_DATA_DEPTH, MAX_CLIENT_DATA_JSON};

    // 32 zero bytes, canonical
    const CHALLENGE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn parse(json: &str) -> Result<ClientData, ErrorKind> {
        ClientData::parse(json.as_bytes()).map_err(|e| e.kind())
    }

    #[test]
    fn members_are_read() {
        let json = format!(
            r#" {{"type":"webauthn.get","challenge":"{CHALLENGE}","origin":"https://a.example","crossOrigin":true,"topOrigin":"https://b.example"}} "#
        );
        let data = parse(&json);
        assert_eq!(data.as_ref().map(|d| d.kind.as_str()), Ok("webauthn.get"));
        assert_eq!(data.as_ref().map(|d| d.challenge.clone()), Ok(vec![0; 32]));
        assert_eq!(
            data.as_ref().map(|d| d.origin.as_str()),
            Ok("https://a.example")
        );
        assert_eq!(data.as_ref().map(|d| d.cross_origin), Ok(Some(true)));
        assert_eq!(
            data.map(|d| d.top_origin),
            Ok(Some("https://b.example".to_string()))
        );
        let bare = parse("{}");
        assert_eq!(
            bare.as_ref()
                .map(|d| (d.kind.as_str(), d.origin.as_str(), d.cross_origin)),
            Ok(("", "", None))
        );
        assert_eq!(
            bare.map(|d| (d.challenge, d.top_origin)),
            Ok((vec![], None))
        );
        assert_eq!(
            parse(r#"{"crossOrigin":false}"#).map(|d| d.cross_origin),
            Ok(Some(false))
        );
    }

    #[test]
    fn challenge_is_canonical_and_32_bytes() {
        for text in [
            &CHALLENGE[1..],
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert_eq!(
                parse(&format!(r#"{{"challenge":"{text}"}}"#)).map(|d| d.challenge),
                Ok(vec![]),
                "{text}"
            );
        }
    }

    #[test]
    fn the_input_is_one_bom_and_utf8() {
        assert!(parse("\u{feff}{}").is_ok());
        assert_eq!(parse("\u{feff}\u{feff}{}"), Err(ErrorKind::Malformed));
        assert_eq!(
            ClientData::parse(&[b'{', 0xff, b'}']).map_err(|e| e.kind()),
            Err(ErrorKind::Malformed)
        );
        assert_eq!(
            ClientData::parse(&[]).map_err(|e| e.kind()),
            Err(ErrorKind::Malformed)
        );
    }

    #[test]
    fn strings_decode_their_escapes() {
        let origin = |text: &str| parse(&format!(r#"{{"origin":"{text}"}}"#)).map(|d| d.origin);
        assert_eq!(
            origin(r#"\"\\\/\b\f\n\r\t\u0041\u00e9"#).as_deref(),
            Ok("\"\\/\u{8}\u{c}\n\r\tA\u{e9}")
        );
        assert_eq!(origin(r"\ud83d\ude00").as_deref(), Ok("\u{1f600}"));
        assert_eq!(origin("\u{1f600}\u{e9}").as_deref(), Ok("\u{1f600}\u{e9}"));
        for bad in [
            r"\ud83d",
            r"\ud83dx",
            r"\ud83d\u0041",
            r"\ude00",
            r"\x",
            r"\u12",
            r"\u+123",
            r"\u12g4",
            "\u{1f}",
            "\n",
        ] {
            assert_eq!(origin(bad), Err(ErrorKind::Malformed), "{bad}");
        }
        assert_eq!(parse(r#"{"origin":"abc"#), Err(ErrorKind::Malformed));
    }

    #[test]
    fn shapes_are_checked() {
        for bad in [
            r#"{"type":1}"#,
            r#"{"origin":null}"#,
            r#"{"challenge":[]}"#,
            r#"{"topOrigin":true}"#,
            r#"{"crossOrigin":"true"}"#,
            r#"{"crossOrigin":null}"#,
            r#"{"origin":"a","origin":"b"}"#,
            r#"{"x":1,"x":2}"#,
            r#"{"origin":"a"} x"#,
            r#"{"origin":"a"}{}"#,
            "[]",
            r#""a""#,
            "1",
            "",
            "{",
            "}",
            r#"{"a" 1}"#,
            r#"{"a":1,}"#,
            r#"{,}"#,
            r#"{1:1}"#,
            r#"{"a":}"#,
            r#"{"a":1 "b":2}"#,
        ] {
            assert_eq!(parse(bad), Err(ErrorKind::Malformed), "{bad}");
        }
    }

    #[test]
    fn unchecked_members_are_skipped_by_the_grammar() {
        for good in [
            r#"{"a":[]}"#,
            r#"{"a":{}}"#,
            r#"{"a":[1,"x",[true,false,null],{"b":-0.5e+3}]}"#,
            r#"{"a":0,"b":-12,"c":1E5,"d":0.25,"e":1e-2}"#,
            "{\"a\" :\t\n\r [ 1 , 2 ] }",
            r#"{"a":null,"b":true,"c":false}"#,
            r#"{ }"#,
        ] {
            assert!(parse(good).is_ok(), "{good}");
        }
        for bad in [
            "01", "1.", ".5", "1e", "1e+", "-", "--1", "tru", "nul", "falsy", "[1,]", "[1 2]", "[",
            "[,1]", "+1", "0x1",
        ] {
            assert_eq!(
                parse(&format!(r#"{{"a":{bad}}}"#)),
                Err(ErrorKind::Malformed),
                "{bad}"
            );
        }
    }

    #[test]
    fn nesting_and_size_are_bounded() {
        let nested = |open: &str, close: &str, depth: usize| {
            format!(r#"{{"a":{}0{}}}"#, open.repeat(depth), close.repeat(depth))
        };
        for (open, close) in [("[", "]"), (r#"{"a":"#, "}")] {
            assert!(parse(&nested(open, close, MAX_CLIENT_DATA_DEPTH - 1)).is_ok());
            assert_eq!(
                parse(&nested(open, close, MAX_CLIENT_DATA_DEPTH)),
                Err(ErrorKind::TooLarge)
            );
        }
        let padded = |len: usize| format!("{{}}{}", " ".repeat(len - 2));
        assert!(parse(&padded(MAX_CLIENT_DATA_JSON)).is_ok());
        assert_eq!(
            parse(&padded(MAX_CLIENT_DATA_JSON + 1)),
            Err(ErrorKind::TooLarge)
        );
    }
}
