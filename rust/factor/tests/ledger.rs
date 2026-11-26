//! The Type claims of CONTRACT.md: each case fails to compile, each twin compiles, and every file on disk runs.
use std::path::{Path, PathBuf};

// the ui cases and twins on disk; a glob that matched nothing would pass while measuring nothing
const CASES: usize = 31;

#[test]
fn ledger() {
    let cases = |dir: &str| -> Vec<PathBuf> {
        testkit::fixture::paths(Path::new(dir))
            .into_iter()
            .filter(|path| path.extension().is_some_and(|x| x == "rs"))
            .collect()
    };
    let (fail, pass) = (cases("tests/ui/fail"), cases("tests/ui/pass"));
    assert_eq!((fail.len(), pass.len()), (CASES, CASES), "cases and twins");
    let t = trybuild::TestCases::new();
    fail.iter().for_each(|path| t.compile_fail(path));
    pass.iter().for_each(|path| t.pass(path));
}
