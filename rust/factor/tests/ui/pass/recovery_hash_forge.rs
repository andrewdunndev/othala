#![allow(dead_code, unused_imports)]
use factor::*;
struct Mine(base::Digest);
fn forge() {
    let _ = Mine(base::Digest::from_bytes([0; 32]));
}
fn main() {}
