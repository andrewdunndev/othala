#![allow(dead_code)]
trait Local {
    const ALG: jose::JweAlg;
}
struct Mine;
impl jose::KeyAlg for Mine {
    const ALG: jose::JweAlg = jose::JweAlg::A128Kw;
}
fn main() {}
