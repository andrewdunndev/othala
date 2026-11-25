#![allow(dead_code)]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Session(base::Secret<32>),
}
impl base::StoreKey for Key {
    fn scope(&self) -> base::Scope {
        base::Scope::Global
    }
}
fn main() {}
