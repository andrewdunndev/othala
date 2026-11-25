//! Committed fixture files read at test time (fuzz corpora, ui cases).
#![expect(
    clippy::expect_used,
    clippy::disallowed_methods,
    reason = "fixtures are files by nature, and one that does not load fails its test"
)]
use std::path::{Path, PathBuf};

/// Every path in `dir`, sorted.
pub fn paths(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .expect("fixture directory")
        .map(|entry| entry.expect("fixture entry").path())
        .collect();
    out.sort();
    out
}

/// Every file in `dir`, sorted by name, as (name, bytes).
pub fn files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    paths(dir)
        .into_iter()
        .map(|path| {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            (name, std::fs::read(&path).expect("fixture file"))
        })
        .collect()
}
