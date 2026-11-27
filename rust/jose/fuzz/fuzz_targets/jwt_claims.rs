#![no_main]
#[path = "../property/jwt_claims.rs"]
mod property;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _outcome = property::check(data);
});
