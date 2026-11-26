#![allow(dead_code, unused_imports)]
use factor::ErrorKind::*;
fn code(k: factor::ErrorKind) -> u8 {
    match k {
        Malformed | TooLarge | Unsupported | WeakCost | WeakKey | PasswordLength | OutOfRange
        | OutOfMemory | _ => 0,
    }
}
fn main() {}
