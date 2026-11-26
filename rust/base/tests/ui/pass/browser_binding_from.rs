#![allow(dead_code)]
type S = base::Secret<32>;
type D = base::Digest;
fn bind(held: &S) -> base::BrowserBinding {
    base::BrowserBinding::from(held)
}
fn main() {}
