#![allow(dead_code, unused_imports)]
use factor::*;
struct Mine {
    seen: Option<(base::Version, Attempts)>,
    at: base::UnixTime,
}
fn forge() {
    let _ = Permit { seen: None, at: base::UnixTime::new(0) };
}
fn main() {}
