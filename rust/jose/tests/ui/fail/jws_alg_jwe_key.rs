#![allow(dead_code)]
fn f<A: jose::Alg>(_key: &jose::EncryptKey<A>) {}
fn main() {}
