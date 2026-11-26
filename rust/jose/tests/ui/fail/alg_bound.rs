#![allow(dead_code)]
fn f<A: jose::Alg, B: jose::Alg>(key: jose::VerifyKey<A>) -> jose::VerifyKey<B> {
    key
}
fn main() {}
