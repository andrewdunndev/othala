#![allow(dead_code)]
fn f<K: jose::TokenKind>(issuer: jose::Issuer, leeway: jose::Leeway) {
    let _ = jose::Policy::<K>::read_back(issuer, leeway, jose::Expiry::Unchecked);
}
fn main() {}
