#![allow(dead_code)]
type T = base::SecretBytes;
fn needs<C: PartialEq>() {}
fn main() {
    needs::<T>();
}
