//! `recovery_code_parse`: `RecoveryCode::parse` is `TooLarge` over 64 bytes; a parsed code displays as four groups
//! of six Crockford symbols, and its display parses to the same display (CONTRACT R32).
use factor::{ErrorKind, RecoveryCode};

pub(crate) fn check(data: &[u8]) -> Result<(), ErrorKind> {
    let text = String::from_utf8_lossy(data);
    let outcome = RecoveryCode::parse(&text);
    if text.len() > 64 {
        assert_eq!(
            outcome.as_ref().map_err(factor::Error::kind).err(),
            Some(ErrorKind::TooLarge),
            "{text:?}"
        );
    }
    let shown = outcome.map_err(|e| e.kind())?.display().to_string();
    let groups: Vec<&str> = shown.split('-').collect();
    assert!(
        groups.len() == 4
            && groups.iter().all(|g| g.len() == 6
                && g.bytes()
                    .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))),
        "{shown:?}"
    );
    let again = RecoveryCode::parse(&shown).map(|c| c.display().to_string());
    assert_eq!(
        again.as_deref().ok(),
        Some(shown.as_str()),
        "a display parses to itself"
    );
    Ok(())
}
