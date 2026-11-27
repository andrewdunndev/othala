//! Row m3-factor-password: the claims through the public API.
mod common;

use argon2::password_hash::phc::PasswordHash;
use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use base::UnixTime;
use common::{Mem, applied};
use factor::{
    Cost, ErrorKind, Key, Lanes, Memory, Minimum, NewPassword, Passes, Password, PasswordMatch,
    Phc, Record, Rehash, Rejected, Throttle, password_hash, password_verify,
};

type Boxed = Box<dyn std::error::Error>;

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
    assert_eq!(
        argon.verify_password(b"correct horse battery", a.as_str()),
        Ok(())
    );
    assert_eq!(
        argon.verify_password(b"correct horse batterz", a.as_str()),
        Err(argon2::password_hash::Error::PasswordInvalid)
    );
    let again = password_hash(&pw, cost, &mut testkit::seeded(1))?;
    assert_eq!(again.as_str(), a.as_str());
    Ok(())
}

const HEAD: &str = "$argon2id$v=19$m=7168,t=5,p=1$";

fn parsed(text: &str) -> Option<ErrorKind> {
    kind(Phc::parse(text))
}

fn text(params: &str, salt: usize, tag: usize) -> String {
    format!(
        "$argon2id$v=19${params}${}${}",
        "A".repeat(salt),
        "A".repeat(tag)
    )
}

#[test]
fn presented_passwords() -> Result<(), Boxed> {
    assert_eq!(
        kind(Password::presented("")),
        Some(ErrorKind::PasswordLength)
    );
    assert_eq!(kind(Password::presented("x")), None);
    assert_eq!(kind(Password::presented(&"x".repeat(4_096))), None);
    assert_eq!(
        kind(Password::presented(&"x".repeat(4_097))),
        Some(ErrorKind::TooLarge)
    );
    assert_eq!(
        kind(Password::presented(&"é".repeat(2_049))),
        Some(ErrorKind::TooLarge)
    );
    // every byte counts: two passwords that differ only in the 4,096th byte verify apart
    let (a, b) = ("a".repeat(4_096), format!("{}b", "a".repeat(4_095)));
    let stored = password_hash(
        &NewPassword::new(&a, Minimum::SingleFactor)?,
        cost(7_168, 5, 1)?,
        &mut testkit::seeded(9),
    )?;
    assert_eq!(verify(&stored, &a, cost(7_168, 5, 1)?)?.0.map(drop), Ok(()));
    assert!(matches!(
        verify(&stored, &b, cost(7_168, 5, 1)?)?.0,
        Err(Rejected::Wrong)
    ));
    Ok(())
}

#[test]
fn phc_text_is_accepted_only_when_canonical() -> Result<(), Boxed> {
    let ok = text("m=7168,t=5,p=1", 22, 43);
    assert_eq!(parsed(&ok), None);
    assert_eq!(Phc::parse(&ok)?.as_str(), ok);
    let mut e = testkit::seeded(3);
    let own = password_hash(
        &NewPassword::new("a long enough password", Minimum::SingleFactor)?,
        cost(7_168, 5, 1)?,
        &mut e,
    )?;
    assert_eq!(Phc::parse(own.as_str())?.as_str(), own.as_str());
    // a cost below the floor still parses, so older hashes verify and rehash
    assert_eq!(parsed(&text("m=8,t=1,p=1", 22, 43)), None);
    assert_eq!(parsed(&text("m=65536,t=64,p=64", 22, 43)), None);
    let big = format!("{HEAD}{}${}", "A".repeat(22), "A".repeat(43));
    assert_eq!(
        parsed(&format!("{big}{}", "x".repeat(256))),
        Some(ErrorKind::TooLarge)
    );
    for bad in [
        "",
        "garbage",
        "$argon2id$v=19$m=7168,t=5,p=1",
        "$argon2id$v=19$m=7168,t=5,p=1$AAAA",
        "argon2id$v=19$m=7168,t=5,p=1$AAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
    ] {
        assert_eq!(parsed(bad), Some(ErrorKind::Malformed), "{bad}");
    }
    for other in [
        "$argon2i$v=19$m=7168,t=5,p=1$",
        "$argon2d$v=19$m=7168,t=5,p=1$",
        "$scrypt$v=19$m=7168,t=5,p=1$",
    ] {
        let body = format!("{other}{}${}", "A".repeat(22), "A".repeat(43));
        assert_eq!(parsed(&body), Some(ErrorKind::Unsupported), "{other}");
    }
    let tail = format!("{}${}", "A".repeat(22), "A".repeat(43));
    for v in [
        "$argon2id$v=16$m=7168,t=5,p=1$",
        "$argon2id$v=20$m=7168,t=5,p=1$",
        "$argon2id$m=7168,t=5,p=1$",
    ] {
        assert_eq!(
            parsed(&format!("{v}{tail}")),
            Some(ErrorKind::Unsupported),
            "{v}"
        );
    }
    for extra in ["m=7168,t=5,p=1,keyid=AAAA", "m=7168,t=5,p=1,data=AAAA"] {
        assert_eq!(
            parsed(&text(extra, 22, 43)),
            Some(ErrorKind::Unsupported),
            "{extra}"
        );
    }
    // salt 8 to 48 bytes and tag 16 to 64 bytes; N characters of `A` are N * 6 / 8 bytes
    for (salt, tag, ok) in [
        (10, 43, false),
        (11, 43, true),
        (64, 43, true),
        (66, 43, false),
        (22, 20, false),
        (22, 22, true),
        (22, 86, true),
        (22, 87, false),
    ] {
        let want = if ok { None } else { Some(ErrorKind::Malformed) };
        assert_eq!(
            parsed(&text("m=7168,t=5,p=1", salt, tag)),
            want,
            "salt {salt} tag {tag}"
        );
    }
    for params in [
        "m=7,t=5,p=1",
        "m=65,t=5,p=9",
        "m=65537,t=5,p=1",
        "m=7168,t=0,p=1",
        "m=7168,t=65,p=1",
        "m=7168,t=5,p=0",
        "m=7168,t=5,p=65",
        "m=7168,t=5",
        "t=5,m=7168,p=1",
        "m=7168,t=5,p=1,x=1",
        "m=07168,t=5,p=1",
        "m=7168,t=5,p=+1",
    ] {
        assert_eq!(
            parsed(&text(params, 22, 43)),
            Some(ErrorKind::Malformed),
            "{params}"
        );
    }
    // a salt or tag whose last character carries bits past the last byte is another text for the same bytes
    let salty = format!("{HEAD}{}B${}", "A".repeat(21), "A".repeat(43));
    assert_eq!(parsed(&salty), Some(ErrorKind::Malformed));
    let padded = format!("{HEAD}{}==${}", "A".repeat(22), "A".repeat(43));
    assert_eq!(parsed(&padded), Some(ErrorKind::Malformed));
    Ok(())
}

/// One verify of `presented` against `stored`, applied to a fresh store.
fn verify(
    stored: &Phc,
    presented: &str,
    cost: Cost,
) -> Result<(Result<PasswordMatch, Rejected>, Mem), Boxed> {
    let (mut store, mut e, now) = (Mem::new(), testkit::seeded(4), UnixTime::new(100));
    let permit = Throttle::unlimited()
        .check(None, now)
        .map_err(|_| "permit")?;
    let pending = password_verify(
        permit,
        &Password::presented(presented)?,
        stored,
        cost,
        &mut e,
    )?;
    // a password verdict holds the count and nothing else (R3), whatever the verdict
    assert_eq!(
        pending
            .effect()
            .guards()
            .map(|g| **g.key())
            .collect::<Vec<_>>(),
        [Key::Attempts]
    );
    assert!(
        pending.effect().puts().all(|(k, r, x)| *k == Key::Attempts
            && x.is_none()
            && matches!(r, Record::Attempts(_)))
    );
    assert_eq!(pending.effect().deletes().count(), 0);
    let receipt = applied(&mut store, pending.effect(), now).ok_or("apply")?;
    Ok((pending.settle(receipt)?, store))
}

fn hashed(password: &str, c: Cost) -> Result<Phc, Boxed> {
    Ok(password_hash(
        &NewPassword::new(password, Minimum::SingleFactor)?,
        c,
        &mut testkit::seeded(5),
    )?)
}

#[test]
fn verify_matches_and_counts_either_way() -> Result<(), Boxed> {
    let c = cost(7_168, 5, 1)?;
    let stored = hashed("correct horse battery", c)?;
    let (hit, mut store) = verify(&stored, "correct horse battery", c)?;
    let Ok(hit) = hit else {
        return Err("rejected".into());
    };
    assert!(matches!(hit.rehash(), Rehash::Current));
    let (miss, mut other) = verify(&stored, "correct horse batterz", c)?;
    assert!(matches!(miss, Err(Rejected::Wrong)));
    let count = |s: &mut Mem| common::stored(s, Key::Attempts).map(|r| r.record().encode());
    assert_eq!(
        count(&mut store).map(|b| b.len()),
        count(&mut other).map(|b| b.len())
    );
    assert!(count(&mut store).is_some());
    // the permit's time stamps the count, so both rows hold one attempt at time 100
    assert_eq!(count(&mut store), count(&mut other));
    Ok(())
}

/// A hash from `argon2` itself, at parameters and sizes this crate would not write.
fn foreign(
    password: &str,
    (m, t, p): (u32, u32, u32),
    salt: &[u8],
    tag: usize,
) -> Result<Phc, Boxed> {
    let params = Params::new(m, t, p, Some(tag))?;
    let hash: PasswordHash = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_with_salt(password.as_bytes(), salt)?;
    Ok(Phc::parse(&hash.to_string())?)
}

#[test]
fn rehash_only_when_below_the_cost_given() -> Result<(), Boxed> {
    let c = cost(19_456, 2, 1)?;
    let salt16 = [7; 16];
    let base = "$argon2id$v=19$m=19456,t=2,p=1$";
    for (stored, needed) in [
        (foreign("pw-for-rehash", (19_456, 2, 1), &salt16, 32)?, None),
        (foreign("pw-for-rehash", (47_104, 3, 2), &salt16, 32)?, None),
        (
            foreign("pw-for-rehash", (12_288, 2, 1), &salt16, 32)?,
            Some(base),
        ),
        (
            foreign("pw-for-rehash", (19_456, 1, 1), &salt16, 32)?,
            Some(base),
        ),
        (
            foreign("pw-for-rehash", (19_456, 2, 1), &[7; 15], 32)?,
            Some(base),
        ),
        (
            foreign("pw-for-rehash", (19_456, 2, 1), &salt16, 31)?,
            Some(base),
        ),
        (
            foreign("pw-for-rehash", (65_536, 1, 1), &salt16, 32)?,
            Some("$argon2id$v=19$m=65536,t=2,p=1$"),
        ),
        (
            foreign("pw-for-rehash", (12_288, 3, 1), &salt16, 32)?,
            Some("$argon2id$v=19$m=19456,t=3,p=1$"),
        ),
        (
            foreign("pw-for-rehash", (19_456, 1, 4), &salt16, 32)?,
            Some("$argon2id$v=19$m=19456,t=2,p=4$"),
        ),
    ] {
        let (hit, _) = verify(&stored, "pw-for-rehash", c)?;
        let Ok(hit) = hit else {
            return Err("rejected".into());
        };
        match (hit.rehash(), needed) {
            (Rehash::Current, None) => {}
            (Rehash::Needed(new), Some(prefix)) => {
                assert!(new.as_str().starts_with(prefix), "{}", new.as_str());
                assert_eq!(
                    Argon2::default().verify_password(b"pw-for-rehash", new.as_str()),
                    Ok(())
                );
                assert_ne!(new.as_str(), stored.as_str());
            }
            _ => return Err(format!("rehash for {}", stored.as_str()).into()),
        }
        let (miss, _) = verify(&stored, "another-password", c)?;
        assert!(matches!(miss, Err(Rejected::Wrong)));
    }
    Ok(())
}

#[test]
fn debug_names_the_type_only() -> Result<(), Boxed> {
    let new = NewPassword::new("a password of length", Minimum::SingleFactor)?;
    let phc = Phc::parse(&text("m=7168,t=5,p=1", 22, 43))?;
    assert_eq!(format!("{new:?}"), "NewPassword { .. }");
    assert_eq!(
        format!("{:?}", Password::presented("secret")?),
        "Password { .. }"
    );
    assert_eq!(format!("{phc:?}"), "Phc { .. }");
    // the size bound is on bytes: 256 are read, 257 are too many
    let at = |n: usize| format!("{}{}", text("m=7168,t=5,p=1", 22, 43), "x".repeat(n));
    let len = text("m=7168,t=5,p=1", 22, 43).len();
    assert_eq!(parsed(&at(256 - len)), Some(ErrorKind::Malformed));
    assert_eq!(parsed(&at(257 - len)), Some(ErrorKind::TooLarge));
    Ok(())
}
