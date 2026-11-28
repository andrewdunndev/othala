//! Hex readers for vector fields.
use serde::{Deserialize, Deserializer};

fn decode<E: serde::de::Error>(text: &str) -> Result<Vec<u8>, E> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2).unwrap_or(""), 16))
        .collect::<Result<_, _>>()
        .map_err(E::custom)
}

pub(crate) fn hex<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    decode(&String::deserialize(d)?)
}

/// A member that may be absent, which differs from one that is empty.
pub(crate) fn hex_opt<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
    Option::<String>::deserialize(d)?
        .map(|text| decode(&text))
        .transpose()
}

pub(crate) fn hex_list<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
    Vec::<String>::deserialize(d)?
        .iter()
        .map(|text| decode(text))
        .collect()
}
