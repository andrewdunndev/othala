#![allow(dead_code)]
fn f<K: base::StoreKey, R>(b: &mut base::Builder<K, R>, k: K, r: R) {
    b.put(k, r, None);
}
fn main() {}
