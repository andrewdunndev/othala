//! The committed `b64url_decode` fuzz corpus, replayed as a stable test.
#[path = "../fuzz/property.rs"]
mod property;

#[test]
fn b64url_decode_corpus() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus/b64url_decode");
    let files = testkit::fixture::files(&dir);
    assert!(files.len() >= 22, "corpus has {} files", files.len());
    for (name, data) in files {
        let replay = std::panic::catch_unwind(|| property::check(&data));
        assert!(replay.is_ok(), "corpus file {name}");
    }
}
