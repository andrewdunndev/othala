#![no_main]
#[path = "../property/client_data.rs"]
mod property;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _outcome = property::check(data);
});
