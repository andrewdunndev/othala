#![no_main]
#[path = "../property/jwk_decode.rs"]
mod property;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _outcome = property::check(data);
});
