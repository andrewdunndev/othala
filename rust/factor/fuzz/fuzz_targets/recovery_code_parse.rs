#![no_main]
#[path = "../property/recovery_code_parse.rs"]
mod property;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _outcome = property::check(data);
});
