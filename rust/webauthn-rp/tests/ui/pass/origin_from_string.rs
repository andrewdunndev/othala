#![allow(dead_code, unused_imports)]
use webauthn_rp::Origin;
fn f(s: Origin) -> Origin {
    Origin::from(s)
}
fn main() {}
