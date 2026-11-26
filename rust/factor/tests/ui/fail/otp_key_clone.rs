#![allow(dead_code)]
type T = factor::OtpKey;
type U = factor::Cost;
fn needs<C: Clone>() {}
fn main() {
    needs::<T>();
}
