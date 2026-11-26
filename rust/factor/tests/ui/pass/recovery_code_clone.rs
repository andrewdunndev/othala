#![allow(dead_code)]
type T = factor::RecoveryCode;
type U = factor::Cost;
fn needs<C: Clone>() {}
fn main() {
    needs::<U>();
}
