#![allow(dead_code, unused_imports)]
use base::EffectId;
struct Mine([u8; 16]);
fn forge() {
    let _ = Mine([0; 16]);
}
fn main() {}
