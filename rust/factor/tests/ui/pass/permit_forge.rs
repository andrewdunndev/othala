#![allow(dead_code, unused_imports)]
use factor::*;
struct Mine {
    seen: Option<(base::Version, Attempts)>,
    at: base::UnixTime,
}
fn forge() {
    let _ = Mine { seen: None, at: base::UnixTime::new(0) };
}
fn main() {}
