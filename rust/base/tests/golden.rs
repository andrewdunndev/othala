//! Redacted `Debug` output, held by a reviewed golden file.
use base::{Effect, Entropy, Pending, Scope, Secret, SecretBytes, StoreKey};

#[derive(Debug)]
#[allow(dead_code)]
struct Holder {
    token: Secret<16>,
    key: SecretBytes,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct K;

impl StoreKey for K {
    fn scope(&self) -> Scope {
        Scope::Global
    }
}

struct Sevens;

impl Entropy for Sevens {
    fn fill(&mut self, out: &mut [u8]) {
        out.fill(7);
    }
}

#[test]
fn debug_redacts() {
    let holder = Holder {
        token: Secret::new([0x41; 16]),
        key: SecretBytes::new(b"hunter2".to_vec()),
    };
    let mut b = Effect::<K, u8>::builder(&mut Sevens);
    b.expect_absent(K);
    let pending = Pending::new("session granted", b.build().unwrap());
    let got = format!(
        "{:?}\n{:?}\n{holder:?}\n{holder:#?}\n{pending:?}\n",
        Secret::new([0x41u8; 32]),
        SecretBytes::new(vec![0x42; 3])
    );
    assert_eq!(got, include_str!("golden/debug.txt"));
}
