#![allow(dead_code)]
type T = base::SecretBytes;
type U = base::Error;
fn needs<C: core::fmt::Display>() {}
fn main() {
    needs::<T>();
}
