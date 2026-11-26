#![allow(dead_code)]
type T = factor::Password;
type U = factor::Cost;
fn needs<C: Clone>() {}
fn main() {
    needs::<T>();
}
