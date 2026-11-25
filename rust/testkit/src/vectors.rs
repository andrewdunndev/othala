//! The one vector runner: the file hashes and counts as `SOURCES.toml` lists it, every case is visited, and enough ran.
#![expect(
    clippy::expect_used,
    clippy::panic,
    clippy::disallowed_methods,
    clippy::disallowed_macros,
    reason = "a harness reports a failed claim by panicking"
)]
use std::collections::BTreeMap;

use serde::Deserialize;
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};

const SOURCES: &str = include_str!("../../vectors/SOURCES.toml");

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

/// A vector file under `vectors/`, named once; build it with [`crate::vector!`].
#[derive(Clone, Copy, Debug)]
pub struct Vector {
    path: &'static str,
    json: &'static str,
}

impl Vector {
    /// The file at `path` (relative to `vectors/`) with its contents.
    pub const fn new(path: &'static str, json: &'static str) -> Self {
        Self { path, json }
    }
}

/// The [`Vector`] at a path relative to `vectors/`, read at compile time.
#[macro_export]
macro_rules! vector {
    ($path:literal) => {
        $crate::vectors::Vector::new(
            $path,
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/", $path)),
        )
    };
}

#[derive(Deserialize)]
struct Sources {
    source: BTreeMap<String, Source>,
}

#[derive(Deserialize)]
struct Source {
    #[serde(default)]
    files: Vec<Listed>,
}

#[derive(Deserialize)]
struct Listed {
    path: String,
    sha256: String,
    cases: usize,
}

#[derive(Deserialize)]
struct File<C> {
    cases: Vec<C>,
}

/// Runs `check` over every case of `vector`; panics unless the file has the SHA-256 and holds the cases
/// `SOURCES.toml` declares and at least `floor` (nonzero) were checked.
pub fn run<C: DeserializeOwned>(
    vector: Vector,
    floor: usize,
    check: impl FnMut(&C) -> Outcome,
) -> Tally {
    run_against(SOURCES, vector, floor, check)
}

fn run_against<C: DeserializeOwned>(
    sources: &str,
    vector: Vector,
    floor: usize,
    mut check: impl FnMut(&C) -> Outcome,
) -> Tally {
    let path = vector.path;
    let file: File<C> = serde_json::from_str(vector.json).expect("vector file decodes");
    let sources: Sources = toml::from_str(sources).expect("SOURCES.toml decodes");
    let listed: Vec<&Listed> = sources
        .source
        .values()
        .flat_map(|s| &s.files)
        .filter(|f| f.path == path)
        .collect();
    let &[listed] = listed.as_slice() else {
        panic!("{path}: listed {} times in SOURCES.toml", listed.len());
    };
    let declared = listed.cases;
    assert_eq!(
        file.cases.len(),
        declared,
        "{path}: cases in file against SOURCES.toml"
    );
    let sha256: String = Sha256::digest(vector.json)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        sha256, listed.sha256,
        "{path}: SHA-256 of the file against SOURCES.toml"
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

#[cfg(test)]
mod tests {
    use super::{Outcome, Tally, Vector, run_against};

    const SOURCES: &str = r#"
[source."a"]
url = "https://example.invalid/a"
files = [ { path = "a/three.json", sha256 = "70aee6cd93f55814211815ffaf84781c23aba9af5a837dd67bf03a55aa280d92", cases = 3 } ]
[source."b"]
notes = "a source with no files"
"#;
    const THREE: &str = r#"{ "cases": [ { "n": 1 }, { "n": 2 }, { "n": 3 } ] }"#;

    #[derive(serde::Deserialize)]
    struct Case {
        n: u8,
    }

    fn odd(c: &Case) -> Outcome {
        if c.n % 2 == 1 {
            Outcome::Checked
        } else {
            Outcome::NotApplicable
        }
    }

    #[test]
    fn tally_counts_checked_cases() {
        let t: Tally = run_against(SOURCES, Vector::new("a/three.json", THREE), 2, odd);
        assert_eq!((t.total(), t.checked()), (3, 2));
    }

    #[test]
    #[should_panic(expected = "a/three.json: 2 cases checked, floor 3")]
    fn floor_counts_only_checked_cases() {
        run_against(SOURCES, Vector::new("a/three.json", THREE), 3, odd);
    }

    #[test]
    #[should_panic(expected = "0 cases checked")]
    fn all_not_applicable_fails() {
        run_against(
            SOURCES,
            Vector::new("a/three.json", THREE),
            1,
            |_: &Case| Outcome::NotApplicable,
        );
    }

    #[test]
    #[should_panic(expected = "floor 0")]
    fn zero_floor_fails() {
        run_against(SOURCES, Vector::new("a/three.json", THREE), 0, odd);
    }

    #[test]
    #[should_panic(expected = "cases in file against SOURCES.toml")]
    fn total_mismatch_fails() {
        let two = r#"{ "cases": [ { "n": 1 }, { "n": 3 } ] }"#;
        run_against(SOURCES, Vector::new("a/three.json", two), 1, odd);
    }

    #[test]
    #[should_panic(expected = "a/three.json: SHA-256 of the file against SOURCES.toml")]
    fn altered_file_fails() {
        let altered = r#"{ "cases": [ { "n": 1 }, { "n": 2 }, { "n": 5 } ] }"#;
        run_against(SOURCES, Vector::new("a/three.json", altered), 1, odd);
    }

    #[test]
    #[should_panic(expected = "listed 0 times")]
    fn unlisted_file_fails() {
        run_against(SOURCES, Vector::new("a/other.json", THREE), 1, odd);
    }
}
