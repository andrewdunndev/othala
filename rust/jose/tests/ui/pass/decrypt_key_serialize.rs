#![allow(dead_code, unused_imports)]
use serde::Serialize;
fn needs<T: Sized>() {}
fn f<K: jose::KeyAlg>() {
    needs::<jose::DecryptKey<K>>();
}
fn main() {}
