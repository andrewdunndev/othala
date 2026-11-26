#![allow(dead_code)]
type T = factor::Permit;
type U = factor::Cost;
fn needs<C: Clone>() {}
fn main() {
    needs::<T>();
}
