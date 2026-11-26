// `just canary` appends this to each published crate's src/lib.rs; each line marked `want:` must be that error there.
// aliased so it neither collides with a crate's own `extern crate std` nor needs std in scope in a no_std crate
extern crate std as canary_std;
macro_rules! canary_in_macro {
    ($x:expr) => {
        $x.unwrap() // want: clippy::disallowed_methods
    };
}
/// canary
pub fn canary_macro_unwrap(x: Option<u8>) -> u8 {
    canary_in_macro!(x)
}
macro_rules! canary_panic_in_macro {
    () => {
        panic!("canary") // want: clippy::disallowed_macros
    };
}
/// canary
pub fn canary_macro_panic() {
    canary_panic_in_macro!()
}
/// canary
pub fn canary_unwrap(x: Option<u8>) -> u8 {
    x.unwrap() // want: clippy::unwrap_used
}
/// canary
pub fn canary_expect(x: Option<u8>) -> u8 {
    x.expect("canary") // want: clippy::expect_used
}
/// canary
pub fn canary_panic() {
    panic!("canary") // want: clippy::panic
}
/// canary
pub fn canary_index(x: &[u8]) -> u8 {
    x[0] // want: clippy::indexing_slicing
}
/// canary
pub fn canary_as(x: u16) -> u8 {
    x as u8 // want: clippy::as_conversions
}
/// canary
pub fn canary_print() {
    canary_std::println!("canary") // want: clippy::print_stdout
}
/// canary
pub fn canary_dbg(x: u8) -> u8 {
    canary_std::dbg!(x) // want: clippy::dbg_macro
}
/// canary
pub fn canary_unsafe() {
    unsafe {} // want: unsafe_code
}
pub fn canary_undocumented() {} // want: missing_docs
mod canary_hidden {
    pub fn unreachable() {} // want: unreachable_pub
}
