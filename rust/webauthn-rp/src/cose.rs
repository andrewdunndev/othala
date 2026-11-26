//! COSE keys and algorithms (R5; L3 5.8.5, 6.5.1); ES256 with webauthn-02, the other algorithms with webauthn-08.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "read by the authenticator data parser, webauthn-04"
    )
)]
use p256::elliptic_curve::sec1::FromSec1Point;
use p256::{AffinePoint, Sec1Point};

use crate::cbor::Value;
use crate::error::{Error, ErrorKind};

/// A COSE algorithm this crate verifies.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CoseAlgorithm {
    /// -7, ECDSA P-256 with SHA-256.
    Es256,
    /// -35, ECDSA P-384 with SHA-384.
    Es384,
    /// -8, Ed25519.
    EdDsa,
    /// -257, RSASSA-PKCS1-v1_5 with SHA-256.
    Rs256,
}

/// A credential public key, checked against its algorithm's curve or modulus bounds when parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(dead_code, reason = "ES384, EdDSA and RS256 are built by webauthn-08")]
pub(crate) enum CoseKey {
    /// EC2 P-256, uncompressed coordinates.
    Es256 { x: [u8; 32], y: [u8; 32] },
    /// EC2 P-384, uncompressed coordinates.
    Es384 { x: [u8; 48], y: [u8; 48] },
    /// OKP Ed25519 point.
    EdDsa([u8; 32]),
    /// RSA modulus and exponent, big-endian.
    Rs256 {
        n: alloc::vec::Vec<u8>,
        e: alloc::vec::Vec<u8>,
    },
}

impl CoseKey {
    /// Reads a COSE_Key map; unknown labels are ignored, a defined label of the wrong type is `Malformed`.
    pub(crate) fn parse(value: &Value<'_>) -> Result<Self, Error> {
        let Value::Map(entries) = value else {
            return Err(malformed());
        };
        let (mut kty, mut alg, mut crv, mut x, mut y) = (None, None, None, None, None);
        for (label, v) in entries {
            match label {
                Value::Unsigned(1) => kty = Some(integer(v)?),
                Value::Unsigned(3) => alg = Some(integer(v)?),
                Value::Negative(0) => crv = Some(integer(v)?),
                Value::Negative(1) => x = Some(bytes(v)?),
                Value::Negative(2) => y = Some(bytes(v)?),
                _ => {}
            }
        }
        match (kty.ok_or_else(malformed)?, alg.ok_or_else(malformed)?) {
            (2, -7) => {
                let (Some(1), Some(x), Some(y)) = (crv, x, y) else {
                    return Err(malformed());
                };
                let x: [u8; 32] = x.try_into().map_err(|_| malformed())?;
                let y: [u8; 32] = y.try_into().map_err(|_| malformed())?;
                let point = Sec1Point::from_affine_coordinates(&x.into(), &y.into(), false);
                if AffinePoint::from_sec1_point(&point).into_option().is_some() {
                    Ok(Self::Es256 { x, y })
                } else {
                    Err(malformed())
                }
            }
            _ => Err(Error::new(ErrorKind::Algorithm)),
        }
    }
}

const fn malformed() -> Error {
    Error::new(ErrorKind::Malformed)
}

fn integer(value: &Value<'_>) -> Result<i128, Error> {
    match value {
        Value::Unsigned(n) => Ok(i128::from(*n)),
        Value::Negative(n) => Ok(-1 - i128::from(*n)),
        _ => Err(malformed()),
    }
}

fn bytes<'a>(value: &Value<'a>) -> Result<&'a [u8], Error> {
    match value {
        Value::Bytes(b) => Ok(b),
        _ => Err(malformed()),
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use p256::elliptic_curve::sec1::ToSec1Point;

    use super::CoseKey;
    use crate::cbor::Value;
    use crate::error::{Error, ErrorKind};

    fn point() -> Result<([u8; 32], [u8; 32]), Error> {
        let bad = Error::new(ErrorKind::Malformed);
        let secret = p256::SecretKey::from_slice(&[1; 32]).map_err(|_| bad)?;
        let sec1 = secret.public_key().to_sec1_point(false);
        let (Some(x), Some(y)) = (sec1.x(), sec1.y()) else {
            return Err(bad);
        };
        Ok((
            x.as_slice().try_into().map_err(|_| bad)?,
            y.as_slice().try_into().map_err(|_| bad)?,
        ))
    }

    fn key<'a>(x: &'a [u8], y: &'a [u8], alg: u64) -> Vec<(Value<'a>, Value<'a>)> {
        vec![
            (Value::Unsigned(1), Value::Unsigned(2)),
            (Value::Unsigned(3), Value::Negative(alg)),
            (Value::Negative(0), Value::Unsigned(1)),
            (Value::Negative(1), Value::Bytes(x)),
            (Value::Negative(2), Value::Bytes(y)),
        ]
    }

    fn kind(entries: Vec<(Value<'_>, Value<'_>)>) -> Option<ErrorKind> {
        CoseKey::parse(&Value::Map(entries)).err().map(|e| e.kind())
    }

    #[test]
    fn es256_reads_and_refuses() -> Result<(), Error> {
        let (x, y) = point()?;
        let mut entries = key(&x, &y, 6);
        entries.push((Value::Unsigned(99), Value::Null));
        assert_eq!(
            CoseKey::parse(&Value::Map(entries.clone())),
            Ok(CoseKey::Es256 { x, y })
        );
        assert_eq!(
            CoseKey::parse(&Value::Null),
            Err(Error::new(ErrorKind::Malformed))
        );
        let malformed = Some(ErrorKind::Malformed);
        for drop in 0..5 {
            let mut fewer = entries.clone();
            fewer.remove(drop);
            assert_eq!(kind(fewer), malformed, "member {drop} is required");
        }
        for (at, wrong) in [
            (0, Value::Text("2")),
            (2, Value::Unsigned(2)),
            (3, Value::Text("x")),
            (4, Value::Bytes(&[0; 31])),
        ] {
            let mut entries = entries.clone();
            entries.splice(
                at..=at,
                [(entries.get(at).map_or(Value::Null, |e| e.0.clone()), wrong)],
            );
            assert_eq!(kind(entries), malformed);
        }
        let off_curve = y.map(|b| b ^ 1);
        assert_eq!(kind(key(&x, &off_curve, 6)), malformed);
        assert_eq!(kind(key(&x, &y, 34)), Some(ErrorKind::Algorithm));
        Ok(())
    }
}
