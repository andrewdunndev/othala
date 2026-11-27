//! Authenticator data and attested credential data (R4).
use alloc::vec::Vec;

use crate::cbor::{Order, Value, read};
use crate::cose::CoseKey;
use crate::error::{Error, ErrorKind};
use crate::record::{Aaguid, CredentialId};
use crate::{MAX_AUTHENTICATOR_DATA, MAX_CREDENTIAL_ID};

/// The flags byte: UP.
pub(crate) const UP: u8 = 0x01;
/// UV.
pub(crate) const UV: u8 = 0x04;
/// BE.
pub(crate) const BE: u8 = 0x08;
/// BS.
pub(crate) const BS: u8 = 0x10;
const AT: u8 = 0x40;
const ED: u8 = 0x80;

/// Parsed authenticator data (L3 6.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthData {
    /// `rpIdHash`.
    pub(crate) rp_id_hash: [u8; 32],
    /// The flags byte: UP 0x01, UV 0x04, BE 0x08, BS 0x10, AT 0x40, ED 0x80.
    pub(crate) flags: u8,
    /// `signCount`.
    pub(crate) sign_count: u32,
    /// Attested credential data, present exactly when AT is set.
    pub(crate) attested: Option<AttestedCredential>,
    /// The extensions map's CBOR bytes, present exactly when ED is set.
    pub(crate) extensions: Option<Vec<u8>>,
}

/// Attested credential data (L3 6.5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AttestedCredential {
    /// The AAGUID, as the authenticator reported it.
    pub(crate) aaguid: Aaguid,
    /// The credential id.
    pub(crate) id: CredentialId,
    /// The credential public key, parsed.
    pub(crate) public_key: CoseKey,
    /// The credential public key's CBOR bytes, which tpm, android-key and apple compare with their certified key.
    pub(crate) public_key_cbor: Vec<u8>,
}

impl AuthData {
    /// Reads authenticator data: 37 bytes, then attested credential data exactly when AT is set, then an extensions map exactly when ED is set, then nothing.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_AUTHENTICATOR_DATA {
            return Err(Error::new(ErrorKind::TooLarge));
        }
        let malformed = Error::new(ErrorKind::Malformed);
        let (rp_id_hash, rest) = bytes.split_first_chunk::<32>().ok_or(malformed)?;
        let (&flags, rest) = rest.split_first().ok_or(malformed)?;
        let (count, mut rest) = rest.split_first_chunk::<4>().ok_or(malformed)?;
        let attested = if flags & AT == 0 {
            None
        } else {
            let (aaguid, tail) = rest.split_first_chunk::<16>().ok_or(malformed)?;
            let (len, tail) = tail.split_first_chunk::<2>().ok_or(malformed)?;
            let len = usize::from(u16::from_be_bytes(*len));
            if len > MAX_CREDENTIAL_ID {
                return Err(Error::new(ErrorKind::CredentialIdInvalid));
            }
            let (id, tail) = tail.split_at_checked(len).ok_or(malformed)?;
            let (key, after) = read(tail, Order::Canonical)?;
            let public_key_cbor = tail
                .get(..tail.len() - after.len())
                .ok_or(malformed)?
                .to_vec();
            rest = after;
            Some(AttestedCredential {
                aaguid: Aaguid(*aaguid),
                id: CredentialId::from_bytes(id)?,
                public_key: CoseKey::parse(&key)?,
                public_key_cbor,
            })
        };
        let extensions = if flags & ED == 0 {
            None
        } else {
            let (map, after) = read(rest, Order::Canonical)?;
            if !matches!(map, Value::Map(_)) || !after.is_empty() {
                return Err(malformed);
            }
            let used = core::mem::take(&mut rest);
            Some(used.to_vec())
        };
        if !rest.is_empty() {
            return Err(malformed);
        }
        Ok(Self {
            rp_id_hash: *rp_id_hash,
            flags,
            sign_count: u32::from_be_bytes(*count),
            attested,
            extensions,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use p256::ecdsa::SigningKey;

    use super::{AuthData, BE, BS, UP, UV};
    use crate::cose::CoseKey;
    use crate::error::{Error, ErrorKind};
    use crate::{MAX_AUTHENTICATOR_DATA, MAX_CREDENTIAL_ID};

    const HASH: [u8; 32] = [3; 32];

    fn bad<T>(_: T) -> Error {
        Error::new(ErrorKind::Corrupt)
    }

    fn refused(bytes: &[u8]) -> Option<ErrorKind> {
        AuthData::parse(bytes).err().map(|e| e.kind())
    }

    // an ES256 COSE_Key in canonical order, and the key it holds
    fn cose() -> Result<(Vec<u8>, CoseKey), Error> {
        let point = SigningKey::from_slice(&[7; 32])
            .map_err(bad)?
            .verifying_key()
            .to_sec1_point(false);
        let (x, y) = (point.x().ok_or(bad(()))?, point.y().ok_or(bad(()))?);
        let bytes = [
            &[0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 0x20][..],
            x,
            &[0x22, 0x58, 0x20],
            y,
        ]
        .concat();
        let key = CoseKey::Es256 {
            x: x.as_slice().try_into().map_err(bad)?,
            y: y.as_slice().try_into().map_err(bad)?,
        };
        Ok((bytes, key))
    }

    fn data(flags: u8, tail: &[u8]) -> Vec<u8> {
        [&HASH[..], &[flags], &[0, 0, 1, 2], tail].concat()
    }

    fn attested(id: &[u8], key: &[u8]) -> Vec<u8> {
        [
            &[8; 16][..],
            &u16::try_from(id.len()).unwrap_or(0).to_be_bytes(),
            id,
            key,
        ]
        .concat()
    }

    #[test]
    fn the_fixed_part_is_37_bytes() -> Result<(), Error> {
        let parsed = AuthData::parse(&data(UP | UV | BE | BS, &[]))?;
        assert_eq!(
            (parsed.rp_id_hash, parsed.flags, parsed.sign_count),
            (HASH, 0x1d, 0x102)
        );
        assert_eq!((parsed.attested, parsed.extensions), (None, None));
        let short = data(UP, &[]);
        assert_eq!(
            refused(short.get(..36).unwrap_or(&[])),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(refused(&[]), Some(ErrorKind::Malformed));
        assert_eq!(
            refused(&data(UP, &[0])),
            Some(ErrorKind::Malformed),
            "nothing trails"
        );
        Ok(())
    }

    #[test]
    fn attested_credential_data_is_read_when_at_is_set() -> Result<(), Error> {
        let (key_bytes, key) = cose()?;
        let parsed = AuthData::parse(&data(0x41, &attested(b"cred", &key_bytes)))?;
        let at = parsed.attested.ok_or(bad(()))?;
        assert_eq!(
            (
                at.aaguid.as_bytes(),
                at.id.as_bytes(),
                at.public_key,
                at.public_key_cbor
            ),
            (&[8; 16], &b"cred"[..], key, key_bytes.clone())
        );
        assert_eq!(
            refused(&data(0x41, &[])),
            Some(ErrorKind::Malformed),
            "AT without data"
        );
        assert_eq!(refused(&data(0x41, &[8; 17])), Some(ErrorKind::Malformed));
        assert_eq!(
            refused(&data(0x41, &attested(b"cred", &key_bytes)[..30])),
            Some(ErrorKind::Malformed),
            "truncated id"
        );
        assert_eq!(
            refused(&data(0x41, &attested(b"", &key_bytes))),
            Some(ErrorKind::Malformed),
            "empty id"
        );
        assert_eq!(
            refused(&data(
                0x41,
                &[attested(b"cred", &key_bytes), vec![0]].concat()
            )),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            refused(&data(0x41, &attested(b"cred", &[0xa0]))),
            Some(ErrorKind::Malformed),
            "an empty key"
        );
        assert_eq!(
            refused(&data(0x01, &attested(b"cred", &key_bytes))),
            Some(ErrorKind::Malformed),
            "data without AT trails"
        );
        let reordered = [&[0xa5, 3, 0x26, 1, 2][..], &key_bytes[5..]].concat();
        assert_eq!(
            refused(&data(0x41, &attested(b"cred", &reordered))),
            Some(ErrorKind::Malformed),
            "canonical key order"
        );
        let off_curve = [
            &key_bytes[..key_bytes.len() - 1],
            &[key_bytes.last().map_or(0, |b| b ^ 1)],
        ]
        .concat();
        assert_eq!(
            refused(&data(0x41, &attested(b"cred", &off_curve))),
            Some(ErrorKind::Malformed)
        );
        let long = |n: usize| {
            data(
                0x41,
                &[
                    &[8; 16][..],
                    &u16::try_from(n).unwrap_or(0).to_be_bytes(),
                    &vec![1; n],
                    &key_bytes,
                ]
                .concat(),
            )
        };
        assert_eq!(
            AuthData::parse(&long(MAX_CREDENTIAL_ID))
                .map(|a| a.attested.map(|c| c.id.as_bytes().to_vec())),
            Ok(Some(vec![1; MAX_CREDENTIAL_ID]))
        );
        assert_eq!(
            refused(&long(MAX_CREDENTIAL_ID + 1)),
            Some(ErrorKind::CredentialIdInvalid)
        );
        Ok(())
    }

    #[test]
    fn extensions_are_a_map_exactly_when_ed_is_set() -> Result<(), Error> {
        let parsed = AuthData::parse(&data(0x81, &[0xa1, 0x01, 0x02]))?;
        assert_eq!(parsed.extensions, Some(vec![0xa1, 1, 2]));
        assert_eq!(refused(&data(0x81, &[])), Some(ErrorKind::Malformed));
        assert_eq!(
            refused(&data(0x81, &[0x01])),
            Some(ErrorKind::Malformed),
            "not a map"
        );
        assert_eq!(refused(&data(0x81, &[0xa0, 0])), Some(ErrorKind::Malformed));
        assert_eq!(
            refused(&data(0x81, &[0xa2, 2, 2, 1, 1])),
            Some(ErrorKind::Malformed),
            "canonical order"
        );
        let (key_bytes, _) = cose()?;
        let both = data(0xc1, &[attested(b"c", &key_bytes), vec![0xa0]].concat());
        let parsed = AuthData::parse(&both)?;
        assert_eq!(
            (parsed.attested.is_some(), parsed.extensions),
            (true, Some(vec![0xa0]))
        );
        Ok(())
    }

    #[test]
    fn the_size_is_bounded() {
        let padded = |n: usize| [data(UP, &[]), vec![0; n - 37]].concat();
        assert_eq!(
            refused(&padded(MAX_AUTHENTICATOR_DATA)),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            refused(&padded(MAX_AUTHENTICATOR_DATA + 1)),
            Some(ErrorKind::TooLarge)
        );
    }
}
