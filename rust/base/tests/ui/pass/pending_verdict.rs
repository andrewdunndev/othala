#![allow(dead_code)]
fn f<K: base::StoreKey, R>(p: base::Pending<u8, K, R>) {
    let _ = p.effect();
}
fn main() {}
