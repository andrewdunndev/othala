#![allow(dead_code)]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct K;
impl base::StoreKey for K {
    fn scope(&self) -> base::Scope {
        base::Scope::Global
    }
}
type P = base::Pending<u8, K, u8>;
type O = Option<u8>;
fn leak(p: P) -> Option<u8> {
    let mut out = None;
    let _ = p.map(|v| out = Some(v));
    out
}
fn main() {}
