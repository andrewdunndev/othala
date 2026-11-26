#![allow(dead_code)]
type T = factor::Totp;
type U = factor::Cost;
fn needs<C: PartialEq>() {}
fn main() {
    needs::<U>();
}
