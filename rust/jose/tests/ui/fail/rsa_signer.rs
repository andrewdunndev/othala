#![allow(dead_code)]
type Alg = jose::Rs256;
fn needs<T: jose::Signer<Alg>>() {}
fn f() {
    needs::<jose::SigningKey<Alg>>();
}
fn main() {}
