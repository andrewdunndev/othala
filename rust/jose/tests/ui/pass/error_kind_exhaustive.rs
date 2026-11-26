#![allow(dead_code, unused_imports)]
use jose::ErrorKind::{Malformed, TooLarge};
fn f(kind: jose::ErrorKind) -> u8 {
    match kind {
        Malformed => 0,
        _ => 1,
    }
}
fn main() {}
