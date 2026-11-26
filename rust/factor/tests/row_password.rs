//! Row m3-factor-password: the claims through the public API; verification lands with factor-07.
use argon2::{Argon2, PasswordVerifier};
use factor::{Cost, ErrorKind, Lanes, Memory, Minimum, NewPassword, Passes, password_hash};

fn kind<T>(r: Result<T, factor::Error>) -> Option<ErrorKind> {
    r.err().map(|e| e.kind())
}

fn cost(kib: u32, passes: u32, lanes: u32) -> Result<Cost, factor::Error> {
    Cost::new(Memory::kib(kib), Passes::new(passes), Lanes::new(lanes))
}

#[test]
fn cost_floor_is_the_owasp_points() {
    for (kib, passes) in [
        (47_104, 1),
        (19_456, 2),
        (12_288, 3),
        (9_216, 4),
        (7_168, 5),
    ] {
        assert_eq!(kind(cost(kib, passes, 1)), None);
        assert_eq!(kind(cost(kib - 1, passes, 1)), Some(ErrorKind::WeakCost));
        assert_eq!(kind(cost(kib, passes, 4)), None);
    }
    assert_eq!(kind(cost(7_167, 64, 1)), Some(ErrorKind::WeakCost));
    assert_eq!(kind(cost(0, 1, 1)), Some(ErrorKind::WeakCost));
}

#[test]
fn cost_ranges() {
    assert_eq!(kind(cost(65_536, 1, 1)), None);
    assert_eq!(kind(cost(65_536, 64, 64)), None);
    assert_eq!(kind(cost(65_537, 1, 1)), Some(ErrorKind::OutOfRange));
    assert_eq!(kind(cost(47_104, 65, 1)), Some(ErrorKind::OutOfRange));
    assert_eq!(kind(cost(47_104, 0, 1)), Some(ErrorKind::OutOfRange));
    assert_eq!(kind(cost(47_104, 1, 65)), Some(ErrorKind::OutOfRange));
    assert_eq!(kind(cost(47_104, 1, 0)), Some(ErrorKind::OutOfRange));
    assert_eq!(
        kind(cost(u32::MAX, u32::MAX, u32::MAX)),
        Some(ErrorKind::OutOfRange)
    );
}

#[test]
fn new_password_lengths() {
    let make = |n: usize, c: char, m| NewPassword::new(&c.to_string().repeat(n), m);
    for (min, minimum) in [(15, Minimum::SingleFactor), (8, Minimum::MultiFactor)] {
        assert_eq!(
            kind(make(min - 1, 'a', minimum)),
            Some(ErrorKind::PasswordLength)
        );
        for n in min..=64 {
            assert_eq!(kind(make(n, 'a', minimum)), None);
        }
        // scalar values, not bytes: a two-byte scalar counts once
        assert_eq!(
            kind(make(min - 1, 'é', minimum)),
            Some(ErrorKind::PasswordLength)
        );
        assert_eq!(kind(make(min, 'é', minimum)), None);
    }
    let big = |n| make(n, 'a', Minimum::SingleFactor);
    assert_eq!(kind(big(4_096)), None);
    assert_eq!(kind(big(4_097)), Some(ErrorKind::TooLarge));
    assert_eq!(
        kind(NewPassword::new(&"é".repeat(2_049), Minimum::SingleFactor)),
        Some(ErrorKind::TooLarge)
    );
}

#[test]
fn hash_is_argon2id_v19_with_fresh_salt() -> Result<(), Box<dyn std::error::Error>> {
    let (pw, cost) = (
        NewPassword::new("correct horse battery", Minimum::SingleFactor)?,
        cost(7_168, 5, 1)?,
    );
    let mut e = testkit::seeded(1);
    let (a, b) = (
        password_hash(&pw, cost, &mut e)?,
        password_hash(&pw, cost, &mut e)?,
    );
    assert_ne!(a.as_str(), b.as_str());
    assert!(a.as_str().starts_with("$argon2id$v=19$m=7168,t=5,p=1$"));
    // 16 salt bytes and 32 tag bytes in unpadded base64
    let mut fields = a.as_str().rsplit('$');
    assert_eq!(fields.next().map(str::len), Some(43));
    assert_eq!(fields.next().map(str::len), Some(22));
    let argon = Argon2::default();
    assert!(
        argon
            .verify_password(b"correct horse battery", a.as_str())
            .is_ok()
    );
    assert!(
        argon
            .verify_password(b"correct horse batterz", a.as_str())
            .is_err()
    );
    let again = password_hash(&pw, cost, &mut testkit::seeded(1))?;
    assert_eq!(again.as_str(), a.as_str());
    Ok(())
}
