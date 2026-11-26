#![allow(dead_code, unused_imports)]
use serde::Serialize;
fn needs<T: Serialize>() {}
fn f() {
    needs::<jose::Plaintext>();
}
fn main() {}
