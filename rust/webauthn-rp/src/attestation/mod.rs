//! Attestation statement formats, each compiled only under its own feature (R100); dispatch and `none` (R90).
#[cfg(feature = "android-key")]
mod android_key;

#[cfg(feature = "apple")]
mod apple;

#[cfg(any(
    feature = "packed",
    feature = "tpm",
    feature = "android-key",
    feature = "apple",
    feature = "fido-u2f"
))]
mod chain;

#[cfg(feature = "fido-u2f")]
mod fido_u2f;

#[cfg(feature = "packed")]
mod packed;

#[cfg(feature = "tpm")]
mod tpm;

use alloc::vec::Vec;

use crate::authdata::AuthData;
use crate::cbor::Value;
use crate::error::{Error, ErrorKind};
use crate::trust::AttestationType;

/// What every format's verification reads (L3 8, the verification procedure's inputs).
#[expect(dead_code, reason = "read by the formats of webauthn-08 and later")]
pub(crate) struct Statement<'a> {
    /// `attStmt`.
    pub(crate) att_stmt: &'a Value<'a>,
    /// The authenticator data, parsed.
    pub(crate) auth_data: &'a AuthData,
    /// The authenticator data as signed.
    pub(crate) auth_data_bytes: &'a [u8],
    /// SHA-256 of `clientDataJSON`.
    pub(crate) client_data_hash: [u8; 32],
}

/// A format's verified result: its attestation type and trust path, leaf first (empty for none and self).
pub(crate) struct Verified {
    /// The attestation type.
    pub(crate) kind: AttestationType,
    /// The `x5c` certificates in DER, leaf first.
    pub(crate) x5c: Vec<Vec<u8>>,
}

/// Every format name this crate dispatches, with whether its cargo feature is on.
const FORMATS: [(&str, bool); 1] = [("none", cfg!(feature = "none"))];

/// Verifies `att_stmt` by the procedure of the format named `fmt`, matched byte for byte: an unlisted name is `UnknownFormat`, one whose feature is off `FormatDisabled`.
pub(crate) fn verify(fmt: &str, statement: &Statement<'_>) -> Result<Verified, Error> {
    among(&FORMATS, fmt, statement)
}

fn among(
    formats: &[(&str, bool)],
    fmt: &str,
    statement: &Statement<'_>,
) -> Result<Verified, Error> {
    match formats.iter().find(|(name, _)| *name == fmt) {
        None => Err(Error::new(ErrorKind::UnknownFormat)),
        Some((_, false)) => Err(Error::new(ErrorKind::FormatDisabled)),
        Some(("none", true)) => match statement.att_stmt {
            Value::Map(entries) if entries.is_empty() => Ok(Verified {
                kind: AttestationType::None,
                x5c: Vec::new(),
            }),
            _ => Err(Error::new(ErrorKind::AttestationInvalid)),
        },
        Some((_, true)) => Err(Error::new(ErrorKind::AttestationInvalid)),
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{Statement, among};
    use crate::authdata::AuthData;
    use crate::cbor::Value;
    use crate::error::{Error, ErrorKind};
    use crate::testing::{auth_data, key};
    use crate::trust::AttestationType;

    fn check(fmt: &str, stmt: &Value<'_>) -> Result<Result<AttestationType, ErrorKind>, Error> {
        check_in(&[("none", true)], fmt, stmt)
    }

    fn check_in(
        formats: &[(&str, bool)],
        fmt: &str,
        stmt: &Value<'_>,
    ) -> Result<Result<AttestationType, ErrorKind>, Error> {
        let (_, cose, _) = key()?;
        let bytes = auth_data(&[0; 32], 0x41, 0, b"c", &cose);
        let parsed = AuthData::parse(&bytes)?;
        let statement = Statement {
            att_stmt: stmt,
            auth_data: &parsed,
            auth_data_bytes: &bytes,
            client_data_hash: [0; 32],
        };
        Ok(among(formats, fmt, &statement)
            .map(|v| v.kind)
            .map_err(|e| e.kind()))
    }

    #[test]
    fn none_takes_the_empty_statement_and_formats_match_byte_for_byte() -> Result<(), Error> {
        let empty = Value::Map(vec![]);
        assert_eq!(check("none", &empty)?, Ok(AttestationType::None));
        assert_eq!(
            check("none", &Value::Map(vec![(Value::Unsigned(1), Value::Null)]))?,
            Err(ErrorKind::AttestationInvalid)
        );
        assert_eq!(
            check("none", &Value::Array(vec![]))?,
            Err(ErrorKind::AttestationInvalid)
        );
        for other in ["None", "NONE", "", "none ", "unknown"] {
            assert_eq!(
                check(other, &empty)?,
                Err(ErrorKind::UnknownFormat),
                "{other}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_format_whose_feature_is_off_is_disabled_not_unknown() -> Result<(), Error> {
        let empty = Value::Map(vec![]);
        let formats = [("none", false), ("packed", true)];
        assert_eq!(
            check_in(&formats, "none", &empty)?,
            Err(ErrorKind::FormatDisabled)
        );
        assert_eq!(
            check_in(&formats, "tpm", &empty)?,
            Err(ErrorKind::UnknownFormat)
        );
        Ok(())
    }

    #[test]
    fn a_listed_format_with_no_procedure_is_refused() -> Result<(), Error> {
        let empty = Value::Map(vec![]);
        assert_eq!(
            check_in(&[("packed", true)], "packed", &empty)?,
            Err(ErrorKind::AttestationInvalid)
        );
        Ok(())
    }
}
