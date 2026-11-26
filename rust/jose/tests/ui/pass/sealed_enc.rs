#![allow(dead_code)]
trait Local {
    const ENC: jose::JweEnc;
}
struct Mine;
impl Local for Mine {
    const ENC: jose::JweEnc = jose::JweEnc::A128Gcm;
}
fn main() {}
