#![allow(dead_code, unused_imports)]
use factor::*;
struct Mine {
    rehash: Rehash,
}
fn forge() {
    let _ = PasswordMatch { rehash: Rehash::Current };
}
fn main() {}
