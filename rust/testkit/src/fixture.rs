//! Committed fixture files read at test time (fuzz corpora, ui cases).
#![expect(
    clippy::expect_used,
    clippy::panic,
    clippy::disallowed_methods,
    reason = "fixtures are files by nature, and one that does not load, or panics, fails its test"
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

/// What `run` returns for the corpus file `name`; a panic in it fails the test, naming the file and keeping the message.
pub fn replay<T>(name: &str, run: impl FnOnce() -> T + std::panic::UnwindSafe) -> T {
    std::panic::catch_unwind(run).unwrap_or_else(|payload| {
        let message = payload
            .downcast_ref::<&str>()
            .map(|text| (*text).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_default();
        std::panic::panic_any(format!("corpus file {name} panicked: {message}"))
    })
}
