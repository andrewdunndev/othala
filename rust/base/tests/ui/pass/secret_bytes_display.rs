#![allow(dead_code)]
type T = u8;
fn needs<C: core::fmt::Display>() {}
fn main() {
    needs::<T>();
}
