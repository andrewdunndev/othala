//! The one vector runner: every case is visited, the total matches `SOURCES.toml`, and enough cases ran.
use serde::Deserialize;
use serde::de::DeserializeOwned;

/// What a check did with one case.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The case was checked against the crate.
    Checked,
    /// The case is outside this crate (another encoding, another algorithm).
    NotApplicable,
}

/// The counts a run asserted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tally {
    total: usize,
    checked: usize,
}

impl Tally {
    /// Cases in the file.
    pub const fn total(&self) -> usize {
        self.total
    }

    /// Cases checked against the crate.
    pub const fn checked(&self) -> usize {
        self.checked
    }
}

#[derive(Deserialize)]
struct File<C> {
    cases: Vec<C>,
}

/// Runs `check` over every case of `json` (the file at `path` in `sources`, the text of `vectors/SOURCES.toml`).
pub fn run<C: DeserializeOwned>(
    sources: &str,
    path: &str,
    json: &str,
    floor: usize,
    mut check: impl FnMut(&C) -> Outcome,
) -> Tally {
    let file: File<C> = serde_json::from_str(json).expect("vector file decodes");
    let declared = declared_cases(sources, path);
    assert_eq!(
        file.cases.len(),
        declared,
        "{path}: cases in file against SOURCES.toml"
    );
    let checked = file
        .cases
        .iter()
        .filter(|c| check(c) == Outcome::Checked)
        .count();
    assert!(
        floor > 0 && checked >= floor,
        "{path}: {checked} cases checked, floor {floor}"
    );
    Tally {
        total: declared,
        checked,
    }
}

fn declared_cases(sources: &str, path: &str) -> usize {
    let needle = format!("path = \"{path}\"");
    let line = sources
        .lines()
        .find(|l| l.contains(&needle))
        .expect("file listed in SOURCES.toml");
    let (_, count) = line
        .split_once("cases = ")
        .expect("cases = N on the file line");
    count
        .trim_end_matches([' ', '}', ','])
        .parse()
        .expect("case count")
}
