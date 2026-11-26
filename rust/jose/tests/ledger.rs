//! The Type claims of CONTRACT.md: each case fails to compile, each twin compiles, and the cases on disk are
//! exactly the `ui:` names CONTRACT.md gives. Cases named `off_*` hold with every feature
//! off and run only then; the others run with every feature on.
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

// a glob or a parse that matched nothing would pass while measuring nothing
const EVERY_FEATURE: usize = 23;
const NO_FEATURE: usize = 3;

#[test]
fn ledger() {
    let features = [
        cfg!(feature = "es512"),
        cfg!(feature = "rsa-decrypt"),
        cfg!(feature = "rsa-sign"),
    ];
    let (every, none) = (features.iter().all(|on| *on), features.iter().all(|on| !on));
    assert!(
        every || none,
        "the ledger runs with every feature on or every feature off"
    );
    let stem = |path: &PathBuf| {
        path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_owned()
    };
    let cases = |dir: &str| -> Vec<PathBuf> {
        testkit::fixture::paths(Path::new(dir))
            .into_iter()
            .filter(|path| path.extension().is_some_and(|x| x == "rs"))
            .collect()
    };

    // `ui:name (Ennnn)` is on disk now; `ui:name (Ennnn, jose-NN)` lands with that item
    let contract = include_str!("../CONTRACT.md");
    let named: BTreeMap<String, (String, bool)> = contract
        .split("ui:")
        .skip(1)
        .filter_map(|rest| {
            let (name, after) = rest.split_once(" (E")?;
            let (code, tail) = (after.get(..4)?, after.get(4..)?);
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
                .then(|| {
                    (
                        name.to_owned(),
                        (format!("error[E{code}]"), tail.starts_with(')')),
                    )
                })
        })
        .collect();
    let now: BTreeSet<String> = named
        .iter()
        .filter(|(_, (_, now))| *now)
        .map(|(n, _)| n.clone())
        .collect();
    let on_disk: BTreeSet<String> = cases("tests/ui/fail").iter().map(stem).collect();
    let late: BTreeSet<&String> = on_disk
        .iter()
        .filter(|n| !now.contains(*n) && !named.contains_key(*n))
        .collect();
    assert!(
        late.is_empty(),
        "cases on disk that CONTRACT.md does not name: {late:?}"
    );
    assert!(
        now.is_subset(&on_disk),
        "CONTRACT.md names cases not on disk: {:?}",
        now.difference(&on_disk)
    );

    let pick = |paths: Vec<PathBuf>| -> Vec<PathBuf> {
        paths
            .into_iter()
            .filter(|path| stem(path).starts_with("off_") == none)
            .collect()
    };
    let (fail, pass) = (pick(cases("tests/ui/fail")), pick(cases("tests/ui/pass")));
    let floor = if every { EVERY_FEATURE } else { NO_FEATURE };
    assert!(
        fail.len() >= floor && fail.len() == pass.len(),
        "cases and twins: {} and {}",
        fail.len(),
        pass.len()
    );
    let t = trybuild::TestCases::new();
    fail.iter().for_each(|path| t.compile_fail(path));
    pass.iter().for_each(|path| t.pass(path));
    drop(t);

    let stderrs: BTreeMap<String, Vec<u8>> = testkit::fixture::files(Path::new("tests/ui/fail"))
        .into_iter()
        .collect();
    for path in &fail {
        let name = stem(path);
        let stderr = stderrs
            .get(&format!("{name}.stderr"))
            .map(|b| String::from_utf8_lossy(b))
            .unwrap_or_default();
        let code = named
            .get(&name)
            .map(|(code, _)| code.as_str())
            .unwrap_or("error[E");
        assert!(
            stderr.starts_with(code),
            "{name}.stderr does not open with {code}"
        );
    }
}
