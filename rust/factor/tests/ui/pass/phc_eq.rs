#![allow(dead_code)]
type T = factor::Phc;
type U = factor::Cost;
fn needs<C: PartialEq>() {}
fn main() {
    needs::<U>();
}
