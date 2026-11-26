#![allow(dead_code, unused_variables)]
use factor::*;
fn twice(t: &Totp, a: Permit, b: Permit, c: &OtpCode, e: &mut impl base::Entropy) {
    let _ = t.verify(a, c, None, e);
    let _ = t.verify(b, c, None, e);
}
fn main() {}
