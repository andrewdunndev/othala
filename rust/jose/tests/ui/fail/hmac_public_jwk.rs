#![allow(dead_code)]
fn f(jwk: &jose::Jwk) {
    let _ = jwk.verify_key::<jose::Hs256>();
}
fn main() {}
