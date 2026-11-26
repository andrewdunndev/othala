//! A hex reader for vector fields.
use serde::{Deserialize, Deserializer};

pub(crate) fn hex<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let text = String::deserialize(d)?;
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2).unwrap_or(""), 16))
        .collect::<Result<_, _>>()
        .map_err(serde::de::Error::custom)
}
