//! The strict CBOR reader (R1 to R3); lands with webauthn-02.
use alloc::vec::Vec;

/// One decoded CBOR data item, borrowing its strings from the input.
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(dead_code, reason = "built by the CBOR reader of webauthn-02")]
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
