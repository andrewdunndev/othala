#![allow(dead_code, unused_imports)]
use webauthn_rp::{CreationOptions, RegistrationCeremony};
fn f(o: CreationOptions) -> RegistrationCeremony {
    o.into()
}
fn main() {}
