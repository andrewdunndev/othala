//! Helpers the unit tests share.
use alloc::vec::Vec;

/// The octets of a hexadecimal string, as Wycheproof and the RFC 7518 vectors write them.
pub(crate) fn hex(text: &str) -> Vec<u8> {
    let parse = |pair: &[u8; 2]| u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok();
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .filter_map(parse)
        .collect()
}
