//! The strict CBOR reader (R1 to R3, R-n).
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "read by the authenticator data parser, webauthn-04"
    )
)]
use alloc::vec::Vec;
use core::str;

use crate::error::{Error, ErrorKind};
use crate::{MAX_CBOR_DEPTH, MAX_CBOR_ITEMS};

/// One decoded CBOR data item, borrowing its strings from the input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Value<'a> {
    /// Major type 0.
    Unsigned(u64),
    /// Major type 1: the value is -1 minus this.
    Negative(u64),
    /// Major type 2.
    Bytes(&'a [u8]),
    /// Major type 3, valid UTF-8.
    Text(&'a str),
    /// Major type 4.
    Array(Vec<Value<'a>>),
    /// Major type 5, keys unique and in canonical order.
    Map(Vec<(Value<'a>, Value<'a>)>),
    /// Simple value 20.
    False,
    /// Simple value 21.
    True,
    /// Simple value 22.
    Null,
}

/// Where map keys must be in CTAP2 canonical order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Order {
    /// Every map, as an authenticator produces it.
    Canonical,
    /// Every map but the top one, which a client may have re-encoded; keys stay unique.
    TopTolerant,
}

/// Reads one item off the front of `bytes` and returns what follows it.
pub(crate) fn read(bytes: &[u8], order: Order) -> Result<(Value<'_>, &[u8]), Error> {
    let mut reader = Reader {
        rest: bytes,
        items: 0,
        order,
    };
    let value = reader.item(1)?;
    Ok((value, reader.rest))
}

/// Reads exactly one item.
pub(crate) fn decode(bytes: &[u8], order: Order) -> Result<Value<'_>, Error> {
    match read(bytes, order)? {
        (value, []) => Ok(value),
        _ => Err(malformed()),
    }
}

const fn malformed() -> Error {
    Error::new(ErrorKind::Malformed)
}

struct Reader<'a> {
    rest: &'a [u8],
    items: usize,
    order: Order,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let (head, rest) = self.rest.split_at_checked(n).ok_or_else(malformed)?;
        self.rest = rest;
        Ok(head)
    }

    fn number(&mut self, width: usize, least: u64) -> Result<u64, Error> {
        let n = self
            .take(width)?
            .iter()
            .fold(0, |n, b| (n << 8) + u64::from(*b));
        if n < least { Err(malformed()) } else { Ok(n) }
    }

    fn argument(&mut self, info: u8) -> Result<u64, Error> {
        match info {
            0..=23 => Ok(u64::from(info)),
            24 => self.number(1, 24),
            25 => self.number(2, 0x100),
            26 => self.number(4, 0x1_0000),
            27 => self.number(8, 0x1_0000_0000),
            _ => Err(malformed()),
        }
    }

    fn length(&mut self, info: u8) -> Result<usize, Error> {
        usize::try_from(self.argument(info)?).map_err(|_| malformed())
    }

    fn item(&mut self, depth: usize) -> Result<Value<'a>, Error> {
        self.items += 1;
        if self.items > MAX_CBOR_ITEMS {
            return Err(Error::new(ErrorKind::TooLarge));
        }
        let (&head, rest) = self.rest.split_first().ok_or_else(malformed)?;
        self.rest = rest;
        let info = head & 0x1f;
        match head >> 5 {
            0 => Ok(Value::Unsigned(self.argument(info)?)),
            1 => Ok(Value::Negative(self.argument(info)?)),
            2 => {
                let n = self.length(info)?;
                Ok(Value::Bytes(self.take(n)?))
            }
            3 => {
                let n = self.length(info)?;
                str::from_utf8(self.take(n)?)
                    .map(Value::Text)
                    .map_err(|_| malformed())
            }
            4 => {
                let n = self.container(info, depth)?;
                (0..n)
                    .map(|_| self.item(depth + 1))
                    .collect::<Result<_, _>>()
                    .map(Value::Array)
            }
            5 => {
                let n = self.container(info, depth)?;
                self.map(n, depth).map(Value::Map)
            }
            7 => match info {
                20 => Ok(Value::False),
                21 => Ok(Value::True),
                22 => Ok(Value::Null),
                _ => Err(malformed()),
            },
            _ => Err(malformed()),
        }
    }

    // each member is at least one byte, so a count past the input is refused before anything is allocated for it
    fn container(&mut self, info: u8, depth: usize) -> Result<usize, Error> {
        if depth > MAX_CBOR_DEPTH {
            return Err(Error::new(ErrorKind::TooLarge));
        }
        let n = self.length(info)?;
        if n > self.rest.len() {
            Err(malformed())
        } else {
            Ok(n)
        }
    }

    fn map(&mut self, n: usize, depth: usize) -> Result<Vec<(Value<'a>, Value<'a>)>, Error> {
        let sorted = self.order == Order::Canonical || depth > 1;
        let mut entries: Vec<(Value<'a>, Value<'a>)> = Vec::with_capacity(n);
        let mut last: &[u8] = &[];
        for _ in 0..n {
            let before = self.rest;
            let key = self.item(depth + 1)?;
            let encoded = before
                .get(..before.len() - self.rest.len())
                .ok_or_else(malformed)?;
            let fresh = if sorted {
                (last.len(), last) < (encoded.len(), encoded)
            } else {
                entries.iter().all(|(k, _)| *k != key)
            };
            if !fresh {
                return Err(malformed());
            }
            last = encoded;
            entries.push((key, self.item(depth + 1)?));
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{Order, Value, decode, read};
    use crate::error::{Error, ErrorKind};
    use crate::{MAX_CBOR_DEPTH, MAX_CBOR_ITEMS};

    fn refused(bytes: &[u8]) -> Option<ErrorKind> {
        decode(bytes, Order::Canonical).err().map(|e| e.kind())
    }

    // maps nested `depth` deep, each inside the last one's key or value
    fn maps(depth: usize, in_key: bool) -> alloc::vec::Vec<u8> {
        (0..depth).fold(vec![0], |inner, _| {
            if in_key {
                [vec![0xa1], inner, vec![0]].concat()
            } else {
                [vec![0xa1, 0], inner].concat()
            }
        })
    }

    #[test]
    fn heads_read_at_their_boundaries() {
        for (bytes, n) in [
            (&[0x18, 0x18][..], 24),
            (&[0x19, 0x01, 0x00], 256),
            (&[0x1a, 0x00, 0x01, 0x00, 0x00], 65_536),
            (&[0x1b, 0, 0, 0, 1, 0, 0, 0, 0], 1 << 32),
            (
                &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                u64::MAX,
            ),
        ] {
            assert_eq!(decode(bytes, Order::Canonical), Ok(Value::Unsigned(n)));
        }
        assert_eq!(decode(&[0x20], Order::Canonical), Ok(Value::Negative(0)));
    }

    #[test]
    fn items_read_as_their_types() {
        assert_eq!(
            decode(&[0x42, 1, 2], Order::Canonical),
            Ok(Value::Bytes(&[1, 2]))
        );
        assert_eq!(
            decode(&[0x62, b'h', b'i'], Order::Canonical),
            Ok(Value::Text("hi"))
        );
        assert_eq!(decode(&[0xf4], Order::Canonical), Ok(Value::False));
        assert_eq!(decode(&[0xf5], Order::Canonical), Ok(Value::True));
        assert_eq!(decode(&[0xf6], Order::Canonical), Ok(Value::Null));
        assert_eq!(decode(&[0x80], Order::Canonical), Ok(Value::Array(vec![])));
        assert_eq!(decode(&[0xa0], Order::Canonical), Ok(Value::Map(vec![])));
        assert_eq!(
            decode(&[0x82, 0x01, 0xa1, 0x02, 0x03], Order::Canonical),
            Ok(Value::Array(vec![
                Value::Unsigned(1),
                Value::Map(vec![(Value::Unsigned(2), Value::Unsigned(3))])
            ]))
        );
        assert_eq!(refused(&[0xf7]), Some(ErrorKind::Malformed));
    }

    #[test]
    fn read_returns_what_follows() {
        assert_eq!(
            read(&[1, 2], Order::Canonical),
            Ok((Value::Unsigned(1), &[2][..]))
        );
        assert_eq!(refused(&[1, 2]), Some(ErrorKind::Malformed));
    }

    #[test]
    fn map_keys_sort_by_length_then_bytes() {
        assert_eq!(
            refused(&[0xa2, 0x18, 0x18, 0, 0x01, 0]),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(refused(&[0xa2, 0x01, 0, 0x18, 0x18, 0]), None);
        assert_eq!(
            refused(&[0xa1, 0x01, 0xa2, 0x02, 0x02, 0x01, 0x01]),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            decode(
                &[0xa1, 0x01, 0xa2, 0x02, 0x02, 0x01, 0x01],
                Order::TopTolerant
            )
            .err()
            .map(|e| e.kind()),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            decode(&[0xa2, 0x02, 0x02, 0x01, 0x01], Order::TopTolerant),
            Ok(Value::Map(vec![
                (Value::Unsigned(2), Value::Unsigned(2)),
                (Value::Unsigned(1), Value::Unsigned(1))
            ]))
        );
    }

    #[test]
    fn declared_length_past_input() {
        assert_eq!(
            refused(&[0x9b, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            refused(&[0xbb, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(refused(&[0x82, 0x01]), Some(ErrorKind::Malformed));
    }

    #[test]
    fn bounds_hold_at_the_limit() {
        let items = [vec![0x99, 0x03, 0xff], vec![0; MAX_CBOR_ITEMS - 1]].concat();
        assert_eq!(refused(&items), None);
        assert_eq!(
            refused(&[items.as_slice(), &[0]].concat()),
            Some(ErrorKind::Malformed)
        );
        let arrays = [vec![0x81; MAX_CBOR_DEPTH], vec![0]].concat();
        assert_eq!(refused(&arrays), None);
        for in_key in [false, true] {
            assert_eq!(refused(&maps(MAX_CBOR_DEPTH, in_key)), None);
            assert_eq!(
                refused(&maps(MAX_CBOR_DEPTH + 1, in_key)),
                Some(ErrorKind::TooLarge)
            );
        }
        assert_eq!(Error::new(ErrorKind::TooLarge).kind(), ErrorKind::TooLarge);
    }
}
