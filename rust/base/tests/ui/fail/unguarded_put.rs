#![allow(dead_code)]
fn f<K: base::StoreKey, R>(b: base::Builder<K, R>, k: K, r: R) -> base::Builder<K, R> {
    b.put(k, r, None)
}
fn main() {}
