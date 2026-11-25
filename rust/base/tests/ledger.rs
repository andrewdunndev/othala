//! The Type claims of CONTRACT.md: each case fails to compile, each twin compiles, and every file on disk runs.
#![expect(
    clippy::disallowed_methods,
    reason = "the ledger lists its own case files"
)]
use std::path::PathBuf;

// the ui cases and twins on disk; a glob that matched nothing would pass while measuring nothing
const CASES: usize = 20;

fn cases(dir: &str) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|x| x == "rs"))
        .collect();
    paths.sort();
    paths
}

#[test]
fn ledger() {
    let (fail, pass) = (cases("tests/ui/fail"), cases("tests/ui/pass"));
    assert_eq!((fail.len(), pass.len()), (CASES, CASES), "cases and twins");
    let t = trybuild::TestCases::new();
    fail.iter().for_each(|path| t.compile_fail(path));
    pass.iter().for_each(|path| t.pass(path));
}
