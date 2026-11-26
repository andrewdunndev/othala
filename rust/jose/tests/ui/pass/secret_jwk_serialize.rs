#![allow(dead_code)]
fn needs<T: Sized>() {}
fn f() {
    needs::<jose::SecretJwk>();
}
fn main() {}
