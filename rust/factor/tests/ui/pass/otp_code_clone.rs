#![allow(dead_code)]
type T = factor::OtpCode;
type U = factor::Cost;
fn needs<C: Clone>() {}
fn main() {
    needs::<U>();
}
