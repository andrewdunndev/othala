#![allow(dead_code)]
fn needs<T: serde::Serialize>() {}
fn f<A: jose::SignAlg>() {
    needs::<jose::SigningKey<A>>();
}
fn main() {}
