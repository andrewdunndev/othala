#![allow(dead_code, unused_imports)]
use webauthn_rp::RpId;
fn f(s: RpId) -> RpId {
    RpId::from(s)
}
fn main() {}
