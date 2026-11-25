#![allow(dead_code)]
type T = base::SecretBytes;
type U = base::Digest;
fn needs<C: Clone>() {}
fn main() {
    needs::<T>();
}
