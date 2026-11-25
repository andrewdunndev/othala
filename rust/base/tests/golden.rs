//! Redacted `Debug` output, held by a reviewed golden file.
use base::{Secret, SecretBytes};

#[derive(Debug)]
#[allow(dead_code)]
struct Holder {
    token: Secret<16>,
    key: SecretBytes,
}

#[test]
fn debug_redacts() {
    let holder = Holder {
        token: Secret::new([0x41; 16]),
        key: SecretBytes::new(b"hunter2".to_vec()),
    };
    let got = format!(
        "{:?}\n{:?}\n{holder:?}\n{holder:#?}\n",
        Secret::new([0x41u8; 32]),
        SecretBytes::new(vec![0x42; 3])
    );
    assert_eq!(got, include_str!("golden/debug.txt"));
}
