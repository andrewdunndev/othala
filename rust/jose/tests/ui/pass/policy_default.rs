#![allow(dead_code)]
fn needs<T: Sized>() {}
fn f<K: jose::TokenKind>() {
    needs::<jose::Policy<K>>();
}
fn main() {}
