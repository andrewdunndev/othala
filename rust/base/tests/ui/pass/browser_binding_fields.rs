#![allow(dead_code, unused_imports)]
use base::{BrowserBinding, Digest};
struct Mine(Digest);
fn forge(d: Digest) {
    let _ = Mine(d);
}
fn main() {}
