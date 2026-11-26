#![allow(dead_code)]
fn needs<T: Clone>() {}
fn f() {
    needs::<jose::Compact>();
}
fn main() {}
