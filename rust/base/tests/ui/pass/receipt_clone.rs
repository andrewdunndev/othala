#![allow(dead_code)]
type T = base::Version;
fn needs<C: Clone>() {}
fn main() {
    needs::<T>();
}
