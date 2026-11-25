use alloc::string::String;
use alloc::vec;

use base64ct::{Base64UrlUnpadded, Encoding};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, ErrorKind};

/// Unpadded base64url (RFC 4648 section 5).
pub fn b64url_encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// The longest text [`b64url_decode`] reads: 64 KiB of symbols, 48 KiB decoded.
pub const MAX_B64URL_TEXT: usize = 65_536;

/// Strict unpadded base64url: padding, a symbol outside the alphabet, or a non-canonical tail is `Malformed`
/// with the partly decoded buffer wiped, so a secret's text may pass through; text past [`MAX_B64URL_TEXT`]
/// is `TooLarge` before anything is allocated.
pub fn b64url_decode(text: &str) -> Result<vec::Vec<u8>, Error> {
    if text.len() > MAX_B64URL_TEXT {
        return Err(Error::new(ErrorKind::TooLarge));
    }
    // sized by the text, an upper bound, so the buffer is never reallocated and left unwiped
    let mut out = Zeroizing::new(vec![0; text.len()]);
    let n = Base64UrlUnpadded::decode(text, &mut out)
        .map_err(|_| Error::new(ErrorKind::Malformed))?
        .len();
    out.truncate(n);
    Ok(core::mem::take(&mut *out))
}

/// Exactly `N` decoded bytes, or `Malformed`; the decode buffer is a stack array that is zeroed on failure, best effort.
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
    use super::{MAX_B64URL_TEXT, b64url_decode, b64url_encode, decode_exact};
    use crate::ErrorKind;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;

    const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    fn malformed(text: &str) -> bool {
        b64url_decode(text).map_err(|e| e.kind()) == Err(ErrorKind::Malformed)
    }

    #[test]
    fn alphabet_edges() {
        for (value, c) in (0..=u8::MAX).zip(ALPHABET.chars()) {
            let text = format!("AAA{c}");
            assert_eq!(b64url_decode(&text), Ok(vec![0, 0, value]));
            assert_eq!(b64url_encode(&[0, 0, value]), text);
        }
        assert_eq!(b64url_encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64url_decode("-_8"), Ok(vec![0xfb, 0xff]));
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
        assert_eq!(b64url_decode("Zg"), Ok(b"f".to_vec()));
        assert_eq!(b64url_decode("Zm8"), Ok(b"fo".to_vec()));
        assert_eq!(b64url_decode(""), Ok(vec![]));
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

    #[test]
    fn text_past_the_cap_is_too_large() {
        assert_eq!(MAX_B64URL_TEXT, 65_536);
        let at_cap = "A".repeat(65_536);
        assert_eq!(b64url_decode(&at_cap).map(|b| b.len()), Ok(49_152));
        for over in [65_537, 65_540] {
            let kind = b64url_decode(&"A".repeat(over)).map_err(|e| e.kind());
            assert_eq!(kind, Err(ErrorKind::TooLarge), "{over} symbols");
        }
    }
}
