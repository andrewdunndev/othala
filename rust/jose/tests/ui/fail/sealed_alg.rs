#![allow(dead_code, unused_imports)]
use jose::Alg;
trait Local {
    const ALG: jose::SigningAlg;
    type Signature;
}
struct Mine;
impl Alg for Mine {
    const ALG: jose::SigningAlg = jose::SigningAlg::Es256;
    type Signature = [u8; 64];
}
fn main() {}
