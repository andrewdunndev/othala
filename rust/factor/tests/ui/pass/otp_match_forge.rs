#![allow(dead_code, unused_imports)]
use factor::*;
struct Mine {
    step: TotpStep,
}
fn forge(s: TotpStep) {
    let _ = Mine { step: s };
}
fn main() {}
