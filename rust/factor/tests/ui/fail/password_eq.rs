#![allow(dead_code)]
type T = factor::Password;
type U = factor::Cost;
fn needs<C: PartialEq>() {}
fn main() {
    needs::<T>();
}
