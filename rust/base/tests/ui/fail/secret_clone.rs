#![allow(dead_code)]
type T = base::Secret<32>;
type U = base::Digest;
fn needs<C: Clone>() {}
fn main() {
    needs::<T>();
}
