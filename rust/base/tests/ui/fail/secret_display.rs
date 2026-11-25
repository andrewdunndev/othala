#![allow(dead_code)]
type T = base::Secret<32>;
fn needs<C: core::fmt::Display>() {}
fn main() {
    needs::<T>();
}
