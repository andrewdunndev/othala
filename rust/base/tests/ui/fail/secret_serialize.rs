#![allow(dead_code)]
type T = base::Secret<32>;
fn needs<C: serde::Serialize>() {}
fn main() {
    needs::<T>();
}
