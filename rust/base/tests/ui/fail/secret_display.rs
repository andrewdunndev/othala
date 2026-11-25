#![allow(dead_code)]
type T = base::Secret<32>;
type U = base::Error;
fn needs<C: core::fmt::Display>() {}
fn main() {
    needs::<T>();
}
