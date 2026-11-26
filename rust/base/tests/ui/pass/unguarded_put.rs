#![allow(dead_code)]
fn f<K: base::StoreKey, R>(b: base::Builder<K, R>, k: K, r: R) -> base::Builder<K, R> {
    b.create(k, r, None)
}
fn main() {}
