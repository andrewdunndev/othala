#![allow(dead_code, unused_imports)]
use jose::KeyAlg;
trait Local {
    const ALG: jose::JweAlg;
}
struct Mine;
impl KeyAlg for Mine {
    const ALG: jose::JweAlg = jose::JweAlg::A128Kw;
}
fn main() {}
