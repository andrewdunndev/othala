//! COSE keys and algorithms (R5; L3 5.8.5, 6.5.1); ES256 with webauthn-02, the other algorithms with webauthn-08.
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
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

impl CoseKey {
    /// The algorithm this key signs under.
    pub(crate) const fn algorithm(&self) -> CoseAlgorithm {
        match self {
            Self::Es256 { .. } => CoseAlgorithm::Es256,
            Self::Es384 { .. } => CoseAlgorithm::Es384,
            Self::EdDsa(_) => CoseAlgorithm::EdDsa,
            Self::Rs256 { .. } => CoseAlgorithm::Rs256,
        }
    }

    /// Verifies `signature` over `message`: ES256 as strict DER, high S accepted; anything else is `Signature`.
    pub(crate) fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let bad = Error::new(ErrorKind::Signature);
        match self {
            Self::Es256 { x, y } => {
                let key =
                    VerifyingKey::from_sec1_bytes(&[&[4][..], x, y].concat()).map_err(|_| bad)?;
                let signature = Signature::from_der(signature).map_err(|_| bad)?;
                key.verify(message, &signature).map_err(|_| bad)
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

    use super::{CoseAlgorithm, CoseKey};
    use crate::cbor::Value;
    use crate::error::{Error, ErrorKind};

    fn bad_key<T>(_: T) -> Error {
        Error::new(ErrorKind::Malformed)
    }

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

    #[test]
    fn es256_signatures_are_strict_der_and_the_algorithm_is_reported() -> Result<(), Error> {
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::{Signature, SigningKey};
        let secret = SigningKey::from_slice(&[1; 32]).map_err(bad_key)?;
        let (x, y) = point()?;
        let key = CoseKey::Es256 { x, y };
        assert_eq!(key.algorithm(), CoseAlgorithm::Es256);
        let signature: Signature = secret.sign(b"message");
        let der = signature.to_der();
        assert_eq!(key.verify(b"message", der.as_bytes()), Ok(()));
        let refused = |m: &[u8], s: &[u8]| key.verify(m, s).err().map(|e| e.kind());
        assert_eq!(
            refused(b"messagf", der.as_bytes()),
            Some(ErrorKind::Signature)
        );
        assert_eq!(
            refused(b"message", &signature.to_bytes()),
            Some(ErrorKind::Signature),
            "raw, not DER"
        );
        assert_eq!(
            refused(
                b"message",
                der.as_bytes()
                    .get(..der.as_bytes().len() - 1)
                    .unwrap_or(&[])
            ),
            Some(ErrorKind::Signature)
        );
        assert_eq!(refused(b"message", &[]), Some(ErrorKind::Signature));
        let (r, s) = signature.split_scalars();
        let high = Signature::from_scalars(
            r,
            p256::NonZeroScalar::new(-*s)
                .into_option()
                .ok_or_else(|| bad_key(()))?,
        )
        .map_err(bad_key)?;
        assert_eq!(
            key.verify(b"message", high.to_der().as_bytes()),
            Ok(()),
            "high S is accepted"
        );
        let other = CoseKey::Es256 {
            x: [1; 32],
            y: [1; 32],
        };
        assert_eq!(
            other
                .verify(b"message", der.as_bytes())
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::Signature)
        );
        let algorithms = [
            (
                CoseKey::Es384 {
                    x: [0; 48],
                    y: [0; 48],
                },
                CoseAlgorithm::Es384,
            ),
            (CoseKey::EdDsa([0; 32]), CoseAlgorithm::EdDsa),
            (
                CoseKey::Rs256 {
                    n: vec![],
                    e: vec![],
                },
                CoseAlgorithm::Rs256,
            ),
        ];
        for (key, algorithm) in algorithms {
            assert_eq!(key.algorithm(), algorithm);
            assert_eq!(
                key.verify(b"m", der.as_bytes()).err().map(|e| e.kind()),
                Some(ErrorKind::Algorithm)
            );
        }
        Ok(())
    }
}
