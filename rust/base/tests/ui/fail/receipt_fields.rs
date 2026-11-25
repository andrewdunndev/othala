#![allow(dead_code, unused_imports)]
use base::Receipt;
struct Mine {
    id: base::EffectId,
}
fn forge(id: base::EffectId) {
    let _ = Receipt { id };
}
fn main() {}
