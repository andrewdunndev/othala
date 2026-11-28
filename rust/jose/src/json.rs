//! The crate's JSON reading discipline: every JSON input is scanned once for duplicate members and depth, then read by
//! serde structs (RFC 7515 section 4, RFC 7517 section 5, RFC 8259 section 4).
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::Cell;
use core::fmt;

use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::{Error, ErrorKind, MAX_ENTRIES, MAX_JSON_DEPTH, MAX_JSON_LEN};

/// A JSON array read into at most `MAX_ENTRIES + 1` elements, the rest skipped unbuilt: a caller that sees more than
/// `MAX_ENTRIES` refuses the document without ever holding it all.
pub(crate) struct Capped<T>(pub(crate) Vec<T>);

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for Capped<T> {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Cap<T>(core::marker::PhantomData<T>);

        impl<'de, T: serde::Deserialize<'de>> serde::de::Visitor<'de> for Cap<T> {
            type Value = Capped<T>;

            fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("an array")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Capped<T>, A::Error> {
                let mut kept = Vec::new();
                while kept.len() <= MAX_ENTRIES {
                    match seq.next_element()? {
                        Some(item) => kept.push(item),
                        None => return Ok(Capped(kept)),
                    }
                }
                while seq.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(Capped(kept))
            }
        }

        d.deserialize_seq(Cap(core::marker::PhantomData))
    }
}

/// Reads JSON for any member named twice or nesting past the bound, which `serde`'s struct reading cannot see.
struct Scan<'c> {
    depth: usize,
    why: &'c Cell<ErrorKind>,
}

impl<'de> DeserializeSeed<'de> for Scan<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Scan<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        self.nest()?;
        while seq.next_element_seed(self.deeper())?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        self.nest()?;
        let mut seen = BTreeSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if !seen.insert(name) {
                self.why.set(ErrorKind::DuplicateMember);
                return Err(serde::de::Error::custom("duplicate member"));
            }
            map.next_value_seed(self.deeper())?;
        }
        Ok(())
    }
}

impl<'c> Scan<'c> {
    const fn deeper(&self) -> Self {
        Self {
            depth: self.depth + 1,
            why: self.why,
        }
    }

    fn nest<E: serde::de::Error>(&self) -> Result<(), E> {
        if self.depth > MAX_JSON_DEPTH {
            self.why.set(ErrorKind::TooLarge);
            return Err(E::custom("too deep"));
        }
        Ok(())
    }
}

/// `TooLarge` past the length or depth bound, `DuplicateMember` for a name used twice, `Malformed` for anything
/// that is not one JSON text.
pub(crate) fn scan(json: &[u8]) -> Result<(), Error> {
    if json.len() > MAX_JSON_LEN {
        return Err(ErrorKind::TooLarge.into());
    }
    let why = Cell::new(ErrorKind::Malformed);
    let mut de = serde_json::Deserializer::from_slice(json);
    Scan {
        depth: 1,
        why: &why,
    }
    .deserialize(&mut de)
    .and_then(|()| de.end())
    .map_err(|_| why.get().into())
}

/// A `T` read from a JSON object only: serde's struct-from-array form is refused, so an array never fills the members
/// of an all-optional struct with defaults.
pub(crate) struct Object<T>(pub(crate) T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Map<T>(core::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for Map<T> {
            type Value = Object<T>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object")
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Object<T>, A::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(map)).map(Object)
            }
        }

        d.deserialize_map(Map(core::marker::PhantomData))
    }
}

/// A member that must hold a `T` when it is named: JSON `null` is an ill-typed member, never an absent one.
pub(crate) fn named<'de, T: Deserialize<'de>, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::ToString as _;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::{Capped, Scan, scan};
    use crate::{ErrorKind, MAX_ENTRIES, MAX_JSON_DEPTH, MAX_JSON_LEN};

    #[test]
    fn capped_arrays_keep_one_past_the_bound() {
        let json = |n: usize| format!("[{}]", vec!["1"; n].join(","));
        let read = |n: usize| {
            serde_json::from_str::<Capped<u8>>(&json(n))
                .map(|c| c.0.len())
                .ok()
        };
        assert_eq!(read(MAX_ENTRIES), Some(MAX_ENTRIES));
        assert_eq!(read(MAX_ENTRIES + 1), Some(MAX_ENTRIES + 1));
        assert_eq!(read(1000), Some(MAX_ENTRIES + 1));
        let wrong = serde_json::from_str::<Capped<u8>>("5").err();
        assert!(wrong.is_some_and(|e| e.to_string().contains("an array")));
    }

    #[test]
    fn expectation_text() {
        let why = core::cell::Cell::new(ErrorKind::Malformed);
        let scan = Scan {
            depth: 1,
            why: &why,
        };
        let error: serde_json::Error =
            serde::de::Error::invalid_type(serde::de::Unexpected::Bool(true), &scan);
        assert!(alloc::string::ToString::to_string(&error).contains("expected JSON"));
    }

    #[test]
    fn scan_bounds() {
        let kind = |json: &str| scan(json.as_bytes()).err().map(|e| e.kind());
        assert_eq!(kind("{\"a\":1,\"b\":[true,null,1.5,-1,\"s\",{}]}"), None);
        assert_eq!(kind("{\"a\":1,\"a\":2}"), Some(ErrorKind::DuplicateMember));
        assert_eq!(
            kind("{\"a\":1,\"\\u0061\":2}"),
            Some(ErrorKind::DuplicateMember)
        );
        assert_eq!(
            kind("[{\"a\":{\"b\":1,\"b\":1}}]"),
            Some(ErrorKind::DuplicateMember)
        );
        assert_eq!(kind("{\"a\":1} x"), Some(ErrorKind::Malformed));
        assert_eq!(kind("{\"a\":"), Some(ErrorKind::Malformed));
        let nested = |depth: usize| format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        assert_eq!(kind(&nested(MAX_JSON_DEPTH)), None);
        assert_eq!(kind(&nested(MAX_JSON_DEPTH + 1)), Some(ErrorKind::TooLarge));
        let objects = |depth: usize| format!("{}1{}", "{\"a\":".repeat(depth), "}".repeat(depth));
        assert_eq!(kind(&objects(MAX_JSON_DEPTH)), None);
        assert_eq!(
            kind(&objects(MAX_JSON_DEPTH + 1)),
            Some(ErrorKind::TooLarge)
        );
        let mut padded = Vec::from(b"{}".as_slice());
        padded.resize(MAX_JSON_LEN, b' ');
        assert_eq!(scan(&padded).err().map(|e| e.kind()), None);
        padded.push(b' ');
        assert_eq!(
            scan(&padded).err().map(|e| e.kind()),
            Some(ErrorKind::TooLarge)
        );
    }
}
