//! Fixtures the unit tests share: a key, authenticator data and an attestation object built from their parts.
use alloc::vec;
use alloc::vec::Vec;

use p256::ecdsa::SigningKey;

use crate::cose::CoseKey;
use crate::error::{Error, ErrorKind};

pub(crate) fn bad<T>(_: T) -> Error {
    Error::new(ErrorKind::Corrupt)
}

/// A signing key, its COSE_Key in canonical order, and the key as the crate holds it.
pub(crate) fn key() -> Result<(SigningKey, Vec<u8>, CoseKey), Error> {
    let secret = SigningKey::from_slice(&[7; 32]).map_err(bad)?;
    let point = secret.verifying_key().to_sec1_point(false);
    let (x, y) = (point.x().ok_or(bad(()))?, point.y().ok_or(bad(()))?);
    let cbor = [
        &[0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20][..],
        x,
        &[0x22, 0x58, 0x20],
        y,
    ]
    .concat();
    let public = CoseKey::Es256 {
        x: x.as_slice().try_into().map_err(bad)?,
        y: y.as_slice().try_into().map_err(bad)?,
    };
    Ok((secret, cbor, public))
}

/// Authenticator data with attested credential data: `id`, AAGUID `[8; 16]` and the COSE key.
pub(crate) fn auth_data(
    rp_id_hash: &[u8; 32],
    flags: u8,
    count: u32,
    id: &[u8],
    cose: &[u8],
) -> Vec<u8> {
    let len = u16::try_from(id.len()).unwrap_or(0).to_be_bytes();
    [
        &rp_id_hash[..],
        &[flags],
        &count.to_be_bytes(),
        &[8; 16],
        &len,
        id,
        cose,
    ]
    .concat()
}

fn head(major: u8, len: usize) -> Vec<u8> {
    match u16::try_from(len) {
        Ok(n) if n < 24 => alloc::vec![major << 5 | u8::try_from(n).unwrap_or(0)],
        Ok(n) if n < 256 => alloc::vec![major << 5 | 24, u8::try_from(n).unwrap_or(0)],
        _ => [
            &[major << 5 | 25][..],
            &u16::try_from(len).unwrap_or(0).to_be_bytes(),
        ]
        .concat(),
    }
}

/// An attestation object: `fmt`, the `attStmt` bytes and `authData`, in that order.
pub(crate) fn attestation(fmt: &str, stmt: &[u8], auth_data: &[u8]) -> Vec<u8> {
    let text = |s: &str| [head(3, s.len()), s.as_bytes().to_vec()].concat();
    [
        vec![0xa3],
        text("fmt"),
        text(fmt),
        text("attStmt"),
        stmt.to_vec(),
        text("authData"),
        head(2, auth_data.len()),
        auth_data.to_vec(),
    ]
    .concat()
}
