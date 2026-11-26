#![allow(dead_code)]
fn needs<T: Clone>() {}
fn f<A: jose::Alg>() {
    needs::<jose::VerifyKey<A>>();
}
fn main() {}
