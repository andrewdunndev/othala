#![deny(unused_must_use)]
#![allow(dead_code)]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct K;
impl base::StoreKey for K {
    fn scope(&self) -> base::Scope {
        base::Scope::Global
    }
}
fn decide(e: base::Effect<K, u8>) {
    base::Pending::new(1u8, e);
}
fn main() {}
