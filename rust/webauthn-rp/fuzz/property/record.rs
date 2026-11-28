//! `record`: the input as a stored row; a row that reads encodes back to the same canonical bytes (R15).
use webauthn_rp::{ErrorKind, Record};

pub(crate) fn check(data: &[u8]) -> Result<(), ErrorKind> {
    let record = Record::decode(data).map_err(|e| e.kind())?;
    assert!(
        record.encode().is_ok_and(|bytes| bytes == data),
        "a row that reads is its own canonical encoding"
    );
    Ok(())
}
