#![allow(dead_code)]
type T = base::Digest;
fn needs<C: Clone>() {}
fn main() {
    needs::<T>();
}
