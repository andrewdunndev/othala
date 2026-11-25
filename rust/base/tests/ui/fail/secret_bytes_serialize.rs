#![allow(dead_code)]
type T = base::SecretBytes;
fn needs<C: serde::Serialize>() {}
fn main() {
    needs::<T>();
}
