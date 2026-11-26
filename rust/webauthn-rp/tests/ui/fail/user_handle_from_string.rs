#![allow(dead_code, unused_imports)]
use webauthn_rp::UserHandle;
fn f(s: String) -> UserHandle {
    UserHandle::from(s)
}
fn main() {}
