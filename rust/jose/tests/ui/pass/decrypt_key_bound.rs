#![allow(dead_code)]
fn f<K: jose::KeyAlg, L: jose::KeyAlg>(key: jose::DecryptKey<K>) -> jose::DecryptKey<K> {
    key
}
fn main() {}
