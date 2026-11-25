#![allow(dead_code)]
type T = base::SecretBytes;
fn needs<C: Clone>() {}
fn main() {
    needs::<T>();
}
