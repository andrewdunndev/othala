//! `otp_code_parse`: `OtpCode::parse` is `TooLarge` over 16 bytes, else ok exactly for six or eight ASCII digits
//! (CONTRACT R19); the property is that rule, checked on every input.
use factor::{ErrorKind, OtpCode};

pub(crate) fn check(data: &[u8]) -> Result<(), ErrorKind> {
    let text = String::from_utf8_lossy(data);
    let outcome = OtpCode::parse(&text).map(drop).map_err(|e| e.kind());
    let digits = matches!(text.len(), 6 | 8) && text.bytes().all(|b| b.is_ascii_digit());
    let rule = match text.len() {
        17.. => Err(ErrorKind::TooLarge),
        _ if digits => Ok(()),
        _ => Err(ErrorKind::Malformed),
    };
    assert_eq!(outcome, rule, "{text:?}");
    outcome
}
