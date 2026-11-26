#![allow(dead_code)]
fn needs<T: Sized>() {}
fn f<K: jose::KeyAlg>() {
    needs::<jose::DecryptKey<K>>();
}
fn main() {}
