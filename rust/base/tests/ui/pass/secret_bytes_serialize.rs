#![allow(dead_code)]
type T = u8;
fn needs<C: serde::Serialize>() {}
fn main() {
    needs::<T>();
}
