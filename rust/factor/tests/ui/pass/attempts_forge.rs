#![allow(dead_code, unused_imports)]
use factor::*;
struct Mine {
    count: u32,
    last: base::UnixTime,
}
fn forge() {
    let _ = Mine { count: 0, last: base::UnixTime::new(0) };
}
fn main() {}
