#![allow(dead_code)]
use base::ErrorKind::{
    Empty, Malformed, Overlap, ScopeChanged, SpansDomains, TooLarge, WrongReceipt,
};
fn code(k: base::ErrorKind) -> u8 {
    match k {
        Malformed | Overlap | TooLarge | Empty | ScopeChanged | SpansDomains | _ => 0,
    }
}
fn main() {}
