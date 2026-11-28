//! `record`: the input as a stored row; a row that reads encodes back to bytes that read as an equal row (R15).
use webauthn_rp::{ErrorKind, Record};

pub(crate) fn check(data: &[u8]) -> Result<(), ErrorKind> {
    let record = Record::decode(data).map_err(|e| e.kind())?;
    let again = record
        .encode()
        .ok()
        .and_then(|bytes| Record::decode(&bytes).ok());
    assert!(
        again.as_ref() == Some(&record),
        "a row's own encoding reads back to it"
    );
    Ok(())
}
