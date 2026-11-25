#![allow(dead_code)]
type T = base::Secret<32>;
fn needs<C: PartialEq>() {}
fn main() {
    needs::<T>();
}
