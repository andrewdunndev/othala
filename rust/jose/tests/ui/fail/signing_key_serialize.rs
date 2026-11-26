#![allow(dead_code, unused_imports)]
use serde::Serialize;
fn needs<T: Serialize>() {}
fn f<A: jose::SignAlg>() {
    needs::<jose::SigningKey<A>>();
}
fn main() {}
