#![allow(dead_code)]
fn needs<T: Sized>() {}
fn f<A: jose::SignAlg>() {
    needs::<jose::SigningKey<A>>();
}
fn main() {}
