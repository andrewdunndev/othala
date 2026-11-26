#![allow(dead_code)]
fn f<K: jose::TokenKind, L: jose::TokenKind>(policy: jose::Policy<K>) -> jose::Policy<L> {
    policy
}
fn main() {}
