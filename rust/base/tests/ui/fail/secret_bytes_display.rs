#![allow(dead_code)]
type T = base::SecretBytes;
fn needs<C: core::fmt::Display>() {}
fn main() {
    needs::<T>();
}
