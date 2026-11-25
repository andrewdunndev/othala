use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64UrlUnpadded, Encoding};
use zeroize::Zeroize;

use crate::{Error, ErrorKind};

/// Unpadded base64url (RFC 4648 section 5).
pub fn b64url_encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Strict unpadded base64url: padding, a symbol outside the alphabet, or a non-canonical tail is `Malformed`.
pub fn b64url_decode(text: &str) -> Result<Vec<u8>, Error> {
    Base64UrlUnpadded::decode_vec(text).map_err(|_| Error::new(ErrorKind::Malformed))
}

/// Exactly `N` decoded bytes, or `Malformed` with the buffer wiped.
pub(crate) fn decode_exact<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    let mut out = [0; N];
    let n = Base64UrlUnpadded::decode(text, &mut out).map(<[u8]>::len);
    if n == Ok(N) {
        Ok(out)
    } else {
        out.zeroize();
        Err(Error::new(ErrorKind::Malformed))
    }
}

#[cfg(test)]
mod tests {
    use super::{b64url_decode, b64url_encode, decode_exact};
    use crate::ErrorKind;
    use alloc::format;
    use alloc::string::String;

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
        for c in ["+", "/", " ", "@", "[", "`", "{", ":", "\u{e9}", "\0", "\n"] {
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
        let accepted = |prefix: &str| -> String {
            ALPHABET
                .chars()
                .filter(|c| b64url_decode(&format!("{prefix}{c}")).is_ok())
                .collect()
        };
        assert_eq!(accepted("Z"), "AQgw");
        assert_eq!(accepted("Zm"), "AEIMQUYcgkosw048");
        assert_eq!(accepted("Zm9").len(), 64);
        assert_eq!(b64url_decode("Zg").unwrap(), b"f");
        assert_eq!(b64url_decode("Zm8").unwrap(), b"fo");
        assert_eq!(b64url_decode("").unwrap(), b"");
    }

    #[test]
    fn exact_length() {
        assert_eq!(decode_exact::<2>("Zm8"), Ok(*b"fo"));
        for wrong in ["Zg", "Zm9v", "Zm8=", "Zm9"] {
            assert_eq!(
                decode_exact::<2>(wrong).map_err(|e| e.kind()),
                Err(ErrorKind::Malformed),
                "{wrong}"
            );
        }
    }
}
