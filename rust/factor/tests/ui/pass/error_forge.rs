#![allow(dead_code, unused_imports)]
use factor::*;
struct Mine {
    kind: ErrorKind,
}
fn forge() {
    let _ = Mine { kind: ErrorKind::Malformed };
}
fn main() {}
