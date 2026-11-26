#![allow(dead_code)]
fn needs<T: Sized>() {}
fn f<A: jose::Alg>() {
    needs::<jose::VerifyKey<A>>();
}
fn main() {}
