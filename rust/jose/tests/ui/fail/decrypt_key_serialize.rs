#![allow(dead_code)]
fn needs<T: serde::Serialize>() {}
fn f<K: jose::KeyAlg>() {
    needs::<jose::DecryptKey<K>>();
}
fn main() {}
