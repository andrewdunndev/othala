#![allow(dead_code)]
fn needs<T: Sized>() {}
fn f() {
    needs::<jose::Plaintext>();
}
fn main() {}
