#![allow(dead_code)]
fn f<K: base::StoreKey, R>(b: base::Builder<K, R>, k: K) -> base::Builder<K, R> {
    b.remove(k)
}
fn main() {}
