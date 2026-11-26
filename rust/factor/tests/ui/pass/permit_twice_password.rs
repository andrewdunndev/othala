#![allow(dead_code, unused_variables)]
use factor::*;
fn twice(p: &Password, h: &Phc, c: Cost, a: Permit, b: Permit, e: &mut impl base::Entropy) {
    let _ = password_verify(a, p, h, c, e);
    let _ = password_verify(b, p, h, c, e);
}
fn main() {}
