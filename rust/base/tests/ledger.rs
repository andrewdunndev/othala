//! The Type claims of CONTRACT.md: each case fails to compile, each twin compiles.
#[test]
fn ledger() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/fail/*.rs");
    t.pass("tests/ui/pass/*.rs");
}
