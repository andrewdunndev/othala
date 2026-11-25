//! Committed fixture files read at test time (fuzz corpora).
use std::path::Path;

/// Every file in `dir`, sorted by name, as (name, bytes).
#[expect(
    clippy::disallowed_methods,
    reason = "fixture corpora are files by nature; tests only"
)]
pub fn files(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .expect("fixture directory")
        .map(|entry| {
            let path = entry.expect("fixture entry").path();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            (name, std::fs::read(&path).expect("fixture file"))
        })
        .collect();
    out.sort();
    out
}
