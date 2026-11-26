#![allow(dead_code)]
trait Local {
    const ALG: jose::SigningAlg;
    type Signature;
}
struct Mine;
impl Local for Mine {
    const ALG: jose::SigningAlg = jose::SigningAlg::Es256;
    type Signature = [u8; 64];
}
fn main() {}
