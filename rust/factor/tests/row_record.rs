//! Row m3-factor-record: the committed encoding of each variant, what the codec refuses, and the fuzz corpus replayed.
use factor::{ErrorKind, Record};

#[path = "../fuzz/property.rs"]
mod property;

const NAMES: [&str; 3] = ["attempts", "totp_step", "recovery"];

fn dir(sub: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(sub)
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    text.trim()
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

fn goldens() -> Vec<Vec<u8>> {
    let files = testkit::fixture::files(&dir("tests/golden"));
    NAMES
        .iter()
        .map(|n| {
            let hex = files.iter().find(|(f, _)| f == &format!("{n}.hex"));
            let text = hex.and_then(|(_, b)| String::from_utf8(b.clone()).ok());
            text.and_then(|t| unhex(&t)).unwrap_or_default()
        })
        .collect()
}

fn with(bytes: &[u8], at: usize, byte: u8) -> Vec<u8> {
    let swap = |(i, b): (usize, &u8)| if i == at { byte } else { *b };
    bytes.iter().enumerate().map(swap).collect()
}

fn kind(bytes: &[u8]) -> Option<ErrorKind> {
    Record::decode(bytes).err().map(|e| e.kind())
}

#[test]
fn committed_encodings_decode_to_their_stated_values() {
    let records: Vec<Record> = goldens()
        .iter()
        .filter_map(|b| Record::decode(b).ok())
        .collect();
    assert_eq!(records.len(), NAMES.len());
    let shown: String = records.iter().map(|r| format!("{r:?}\n")).collect();
    assert_eq!(shown, include_str!("golden/debug.txt"));
    let again: Vec<Vec<u8>> = records.iter().map(Record::encode).collect();
    assert_eq!(again, goldens());
}

#[test]
fn what_the_codec_refuses() {
    for golden in goldens() {
        assert!(!golden.is_empty());
        for cut in 0..golden.len() {
            assert_eq!(
                kind(&golden.iter().take(cut).copied().collect::<Vec<_>>()),
                Some(ErrorKind::Malformed),
                "prefix {cut}"
            );
        }
        for extra in [0, 1, 255] {
            let longer = [golden.clone(), vec![extra]].concat();
            assert_eq!(
                kind(&longer),
                Some(ErrorKind::Malformed),
                "trailing {extra}"
            );
        }
        for version in [0, 2, 255] {
            assert_eq!(
                kind(&with(&golden, 0, version)),
                Some(ErrorKind::Malformed),
                "version {version}"
            );
        }
        for tag in [3, 255] {
            assert_eq!(
                kind(&with(&golden, 1, tag)),
                Some(ErrorKind::Malformed),
                "tag {tag}"
            );
        }
        let padded = |n: usize| [golden.clone(), vec![0; n - golden.len()]].concat();
        assert_eq!(kind(&padded(64)), Some(ErrorKind::Malformed));
        assert_eq!(kind(&padded(65)), Some(ErrorKind::TooLarge));
    }
    assert_eq!(kind(&[255; 65]), Some(ErrorKind::TooLarge));
    assert_eq!(kind(&[255; 64]), Some(ErrorKind::Malformed));
}

#[test]
fn record_decode_corpus() {
    let files = testkit::fixture::files(&dir("fuzz/corpus/record_decode"));
    assert!(files.len() >= 20, "corpus has {} files", files.len());
    for (name, data) in files {
        testkit::fixture::replay(&name, || property::check(&data));
    }
}
