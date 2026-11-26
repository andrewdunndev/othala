#![allow(dead_code)]
fn needs<T: serde::Serialize>() {}
fn f() {
    needs::<jose::Plaintext>();
}
fn main() {}
