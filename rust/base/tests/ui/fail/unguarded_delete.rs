#![allow(dead_code)]
fn f<K: base::StoreKey, R>(b: &mut base::Builder<K, R>, k: K) {
    b.remove(k);
}
fn main() {}
