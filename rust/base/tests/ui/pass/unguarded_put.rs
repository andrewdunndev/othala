#![allow(dead_code)]
fn f<K: base::StoreKey, R>(b: &mut base::Builder<K, R>, k: K, r: R) {
    b.create(k, r, None);
}
fn main() {}
