//! The `crit` rule JWS and JWE share (RFC 7515 sections 4.1.11 and 5.2, RFC 7516 sections 4.1.13 and 5.2).
use alloc::collections::BTreeSet;
use alloc::string::String;

use crate::{Error, ErrorKind};

/// Every header name a registry defines (RFC 7515 4.1, RFC 7516 4.1, RFC 7518 4, RFC 7797): `crit` may not name one.
const REGISTERED: [&str; 22] = [
    "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit", "b64",
    "enc", "zip", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c", "ppt",
];

/// A token with `crit` anywhere is refused: `crit` outside the protected header (`unprotected`) is `Malformed`, and in
/// it is `CriticalHeader` when it lists one or more extension names the protected header carries, `Malformed`
/// otherwise. No extension is understood, so none is ever accepted.
pub(crate) fn refuse_crit(
    protected: Option<&[String]>,
    protected_names: &BTreeSet<String>,
    unprotected: bool,
) -> Result<(), Error> {
    if unprotected {
        return Err(ErrorKind::Malformed.into());
    }
    let Some(crit) = protected else {
        return Ok(());
    };
    let usable = !crit.is_empty()
        && crit
            .iter()
            .all(|name| !REGISTERED.contains(&name.as_str()) && protected_names.contains(name));
    Err(if usable {
        ErrorKind::CriticalHeader
    } else {
        ErrorKind::Malformed
    }
    .into())
}
