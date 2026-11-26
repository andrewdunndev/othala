#![allow(dead_code)]
fn f<A: jose::Alg, B: jose::Alg>(token: jose::Unsigned<A>) -> jose::Unsigned<A> {
    token
}
fn main() {}
