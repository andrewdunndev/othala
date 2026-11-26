#![allow(dead_code, unused_imports)]
use webauthn_rp::RpId;
fn f(s: String) -> RpId {
    RpId::from(s)
}
fn main() {}
