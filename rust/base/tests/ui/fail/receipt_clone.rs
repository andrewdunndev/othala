#![allow(dead_code)]
type T = base::Receipt;
fn needs<C: Clone>() {}
fn main() {
    needs::<T>();
}
