#![allow(dead_code, unused_imports)]
use factor::*;
struct Mine {
    rehash: Rehash,
}
fn forge() {
    let _ = Mine { rehash: Rehash::Current };
}
fn main() {}
