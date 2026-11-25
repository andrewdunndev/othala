#![allow(dead_code)]
type T = base::Secret<32>;
fn needs<C: Clone>() {}
fn main() {
    needs::<T>();
}
