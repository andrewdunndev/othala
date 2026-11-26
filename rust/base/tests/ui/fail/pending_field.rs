#![allow(dead_code)]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct K;
impl base::StoreKey for K {
    fn scope(&self) -> base::Scope {
        base::Scope::Global
    }
}
struct Mine {
    verdict: u8,
}
fn leak(p: base::Pending<u8, K, u8>, _m: Mine) -> u8 {
    p.verdict
}
fn main() {}
