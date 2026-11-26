#![allow(dead_code)]
type T = base::SecretBytes;
type U = base::Digest;
fn needs<C: serde::Serialize>() {}
fn main() {
    needs::<U>();
}
