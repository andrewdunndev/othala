//! `phc_parse`: `Phc::parse` is `TooLarge` over 256 bytes, and what it accepts is held as the same text, which
//! parses again (CONTRACT R27).
use factor::{ErrorKind, Phc};

pub(crate) fn check(data: &[u8]) -> Result<(), ErrorKind> {
    let text = String::from_utf8_lossy(data);
    let outcome = Phc::parse(&text);
    if text.len() > 256 {
        assert_eq!(
            outcome.as_ref().map_err(factor::Error::kind).err(),
            Some(ErrorKind::TooLarge),
            "{text:?}"
        );
    }
    let phc = outcome.map_err(|e| e.kind())?;
    assert_eq!(
        phc.as_str(),
        text,
        "a parsed PHC string is held as its text"
    );
    let again = Phc::parse(phc.as_str()).map(|p| String::from(p.as_str()));
    assert_eq!(
        again.as_deref().ok(),
        Some(phc.as_str()),
        "a held PHC string parses again"
    );
    Ok(())
}
