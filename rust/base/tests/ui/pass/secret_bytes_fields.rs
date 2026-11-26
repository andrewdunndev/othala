#![allow(dead_code, unused_imports)]
use base::SecretBytes;
struct Mine(Vec<u8>);
fn forge() {
    let _ = Mine(vec![1]);
}
fn main() {}
