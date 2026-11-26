#![no_main]
#[path = "../property.rs"]
mod property;

libfuzzer_sys::fuzz_target!(|data: &[u8]| property::check(data));
