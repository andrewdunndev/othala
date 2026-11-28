//! The Type claims of CONTRACT.md: each case fails with the rustc code CONTRACT.md names, each twin compiles, every
//! file on disk runs, and the `ui:` names in CONTRACT.md are exactly the cases on disk.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

// the ui cases and twins on disk; a glob that matched nothing would pass while measuring nothing
const CASES: usize = 9;
const CONTRACT: &str = include_str!("../CONTRACT.md");

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
    drop(t);
    // a case is cited as `ui:name (Ennnn)`, and its .stderr opens with `error[Ennnn]`
    let cited: BTreeMap<&str, String> = CONTRACT
        .split("ui:")
        .skip(1)
        .filter_map(|rest| {
            let (name, after) = rest.split_once(" (E")?;
            name.chars()
                .all(|c| c.is_ascii_lowercase() || c == '_')
                .then(|| Some((name, format!("error[E{}]", after.get(..4)?))))?
        })
        .collect();
    let stderr: BTreeMap<String, String> = testkit::fixture::files(Path::new("tests/ui/fail"))
        .into_iter()
        .filter_map(|(name, bytes)| {
            let case = name.strip_suffix(".stderr")?.to_owned();
            Some((case, String::from_utf8_lossy(&bytes).into_owned()))
        })
        .collect();
    assert_eq!(
        cited.keys().copied().collect::<Vec<_>>(),
        stderr.keys().map(String::as_str).collect::<Vec<_>>(),
        "ui: names in CONTRACT.md and cases on disk"
    );
    for (name, code) in &cited {
        let opens = stderr
            .get(*name)
            .is_some_and(|s| s.starts_with(code.as_str()));
        assert!(opens, "{name}.stderr does not open with {code}");
    }
}
