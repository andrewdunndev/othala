#![allow(dead_code)]
fn needs<T: PartialEq>() {}
fn f() {
    needs::<jose::Compact>();
}
fn main() {}
