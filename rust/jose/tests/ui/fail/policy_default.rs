#![allow(dead_code)]
fn needs<T: Default>() {}
fn f<K: jose::TokenKind>() {
    needs::<jose::Policy<K>>();
}
fn main() {}
