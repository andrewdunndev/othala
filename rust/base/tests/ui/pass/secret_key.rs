#![allow(dead_code)]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Session(base::Digest),
}
impl base::StoreKey for Key {
    fn scope(&self) -> base::Scope {
        base::Scope::Global
    }
}
fn main() {}
