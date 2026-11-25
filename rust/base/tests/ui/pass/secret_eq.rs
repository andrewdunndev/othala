#![allow(dead_code)]
type T = base::Digest;
fn needs<C: PartialEq>() {}
fn main() {
    needs::<T>();
}
