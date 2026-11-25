use alloc::string::String;
use alloc::vec::Vec;

use crate::{Error, ErrorKind};

/// Unpadded base64url (RFC 4648 section 5).
pub fn b64url_encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut b = [0u8; 3];
        b.iter_mut().zip(chunk).for_each(|(d, s)| *d = *s);
        let [x, y, z] = b;
        let sextets = [
            x >> 2,
            (x & 3) << 4 | y >> 4,
            (y & 15) << 2 | z >> 6,
            z & 63,
        ];
        out.extend(
            sextets
                .iter()
                .take(chunk.len() + 1)
                .map(|&v| char::from(symbol(v))),
        );
    }
    out
}

/// Strict unpadded base64url: padding, a symbol outside the alphabet, or a non-canonical tail is `Malformed`.
pub fn b64url_decode(text: &str) -> Result<Vec<u8>, Error> {
    let malformed = Error::new(ErrorKind::Malformed);
    let mut out = Vec::new();
    for chunk in text.as_bytes().chunks(4) {
        let mut v = [0u8; 4];
        for (d, &c) in v.iter_mut().zip(chunk) {
            *d = sextet(c).ok_or(malformed)?;
        }
        let [a, b, c, d] = v;
        let bytes = [a << 2 | b >> 4, b << 4 | c >> 2, c << 6 | d];
        let keep = match chunk.len() {
            4 => 3,
            3 if c & 3 == 0 => 2,
            2 if b & 15 == 0 => 1,
            _ => return Err(malformed),
        };
        out.extend(bytes.iter().take(keep));
    }
    Ok(out)
}

fn symbol(v: u8) -> u8 {
    match v {
        0..=25 => b'A' + v,
        26..=51 => b'a' + (v - 26),
        52..=61 => b'0' + (v - 52),
        62 => b'-',
        _ => b'_',
    }
}

fn sextet(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{b64url_decode, b64url_encode};
    use crate::ErrorKind;
    use alloc::format;

    const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    fn malformed(text: &str) -> bool {
        b64url_decode(text).map_err(|e| e.kind()) == Err(ErrorKind::Malformed)
    }

    #[test]
    fn alphabet_edges() {
        for (i, c) in ALPHABET.chars().enumerate() {
            let value = u8::try_from(i).unwrap();
            let text = format!("AAA{c}");
            assert_eq!(b64url_decode(&text).unwrap(), [0, 0, value]);
            assert_eq!(b64url_encode(&[0, 0, value]), text);
        }
        assert_eq!(b64url_encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64url_decode("-_8").unwrap(), [0xfb, 0xff]);
    }

    #[test]
    fn padding_is_malformed() {
        assert!(malformed("Zg=="));
        assert!(malformed("Zm8="));
        assert!(malformed("===="));
    }

    #[test]
    fn foreign_symbol_is_malformed() {
        for c in ["+", "/", " ", "@", "[", "`", "{", ":", "\u{e9}", "\0"] {
            assert!(malformed(&format!("AAA{c}")), "{c:?}");
            assert!(malformed(&format!("{c}AAA")), "{c:?}");
        }
    }

    #[test]
    fn lone_symbol_is_malformed() {
        assert!(malformed("Z"));
        assert!(malformed("Zm9vY"));
    }

    #[test]
    fn noncanonical_tail_is_malformed() {
        assert!(malformed("Zh"));
        assert!(malformed("Zm9"));
        assert_eq!(b64url_decode("Zg").unwrap(), b"f");
        assert_eq!(b64url_decode("Zm8").unwrap(), b"fo");
        assert_eq!(b64url_decode("").unwrap(), b"");
    }
}
