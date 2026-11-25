#![allow(dead_code)]
type T = base::Receipt;
type U = base::Version;
fn needs<C: Clone>() {}
fn main() {
    needs::<T>();
}
