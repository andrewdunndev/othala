#![allow(dead_code, unused_variables)]
use factor::*;
fn twice(r: &RecoveryCode, a: Permit, b: Permit, e: &mut impl base::Entropy) {
    let _ = recovery_verify(a, r, None, e);
    let _ = recovery_verify(b, r, None, e);
}
fn main() {}
