#![allow(dead_code)]
type T = base::SecretBytes;
type U = base::Digest;
fn needs<C: PartialEq>() {}
fn main() {
    needs::<U>();
}
