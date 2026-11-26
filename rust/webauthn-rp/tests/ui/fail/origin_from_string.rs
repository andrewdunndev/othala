#![allow(dead_code, unused_imports)]
use webauthn_rp::Origin;
fn f(s: String) -> Origin {
    Origin::from(s)
}
fn main() {}
