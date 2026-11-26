#![allow(dead_code)]
fn f<A: jose::KeyAlg>(_key: &jose::EncryptKey<A>) {}
fn main() {}
