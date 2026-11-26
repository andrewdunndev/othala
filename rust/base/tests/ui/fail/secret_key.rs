#![allow(dead_code)]
type S = base::Secret<32>;
type D = base::Digest;
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Session(S),
}
impl base::StoreKey for Key {
    fn scope(&self) -> base::Scope {
        base::Scope::Global
    }
}
fn main() {}
