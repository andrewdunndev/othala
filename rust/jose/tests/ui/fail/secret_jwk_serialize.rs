#![allow(dead_code)]
fn needs<T: serde::Serialize>() {}
fn f() {
    needs::<jose::SecretJwk>();
}
fn main() {}
