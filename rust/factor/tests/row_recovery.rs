//! Row m3-factor-recovery: generation, the Crockford text and the per-code consume, through the public API.
mod common;

use base::{Digest, Entropy, Guard, Row, UnixTime};
use common::{Mem, applied, stored};
use factor::{
    ErrorKind, Key, Record, RecoveryCode, RecoveryCount, RecoveryHash, Rejected, Throttle,
    recovery_generate, recovery_verify,
};

type Boxed = Box<dyn std::error::Error>;

/// Every byte it fills is `0`, the same bytes on every draw.
struct Same(u8);

impl Entropy for Same {
    fn fill(&mut self, out: &mut [u8]) {
        out.fill(self.0);
    }
}

/// The bytes 1, 2, 3 ... on every draw.
struct Ramp;

impl Entropy for Ramp {
    fn fill(&mut self, out: &mut [u8]) {
        out.iter_mut().zip(1..).for_each(|(slot, n)| *slot = n);
    }
}

fn kind<T>(r: Result<T, factor::Error>) -> Option<ErrorKind> {
    r.err().map(|e| e.kind())
}

fn digest(hex: &str) -> Option<Digest> {
    let bytes = common::unhex(hex)?;
    Some(Digest::from_bytes(bytes.try_into().ok()?))
}

fn count(n: u8) -> Result<RecoveryCount, factor::Error> {
    RecoveryCount::new(n)
}

#[test]
fn count_bounds() {
    assert_eq!(kind(count(0)), Some(ErrorKind::OutOfRange));
    assert_eq!(kind(count(1)), None);
    assert_eq!(kind(count(16)), None);
    assert_eq!(kind(count(17)), Some(ErrorKind::OutOfRange));
}

#[test]
fn one_row_per_code_under_the_digest_of_its_bytes() -> Result<(), Boxed> {
    // 15 zero bytes digest to this SHA-256 (CONTRACT R31)
    let zero = digest("5322fecfc92a5e3248a297a3df3eddfb9bd9049504272e4f572b87fa36d4b3bd")
        .ok_or("digest")?;
    let pending = recovery_generate(count(1)?, &mut Same(0))?;
    let key = Key::Recovery(zero);
    assert_eq!(
        pending.effect().guards().collect::<Vec<_>>(),
        [Guard::Absent(&key)]
    );
    let row = Record::decode(&[&[1, 2][..], zero.as_bytes()].concat())?;
    assert_eq!(
        pending.effect().puts().collect::<Vec<_>>(),
        [(&key, &row, None)]
    );
    let mut store = Mem::new();
    let receipt = applied(&mut store, pending.effect(), UnixTime::new(0)).ok_or("apply")?;
    let codes = pending.settle(receipt)?;
    assert_eq!(codes.len(), 1);
    assert!(
        codes
            .iter()
            .all(|c| c.key() == key && c.display().to_string() == "000000-000000-000000-000000")
    );
    // a repeated draw is an error, never one merged row
    assert_eq!(
        kind(recovery_generate(count(2)?, &mut Same(7))),
        Some(ErrorKind::Internal)
    );
    assert_eq!(kind(recovery_generate(count(1)?, &mut Same(7))), None);
    let pending = recovery_generate(count(16)?, &mut testkit::seeded(8))?;
    assert_eq!(pending.effect().puts().count(), 16);
    Ok(())
}

#[test]
fn crockford_text() -> Result<(), Boxed> {
    let text = |t: &str| RecoveryCode::parse(t).map(|c| c.display().to_string());
    let shown = "041061-050R3G-G28A1C-60T3GF";
    let ramp = recovery_generate(count(1)?, &mut Ramp)?;
    let mut store = Mem::new();
    let receipt = applied(&mut store, ramp.effect(), UnixTime::new(0)).ok_or("apply")?;
    let codes = ramp.settle(receipt)?;
    assert_eq!(
        codes
            .iter()
            .map(|c| c.display().to_string())
            .collect::<Vec<_>>(),
        [shown]
    );
    // bytes 1 to 15 digest to the key of the parsed text
    assert_eq!(
        codes.first().map(RecoveryCode::key),
        RecoveryCode::parse(shown)
            .ok()
            .as_ref()
            .map(RecoveryCode::key)
    );
    for same in [
        "041061050r3gg28a1c60t3gf",
        "0410 6105-0R3G g28a-1c60T3GF ",
        "O41O6l-O5OR3G-G28AlC-6OT3GF",
        "O41O6I05OR3GG28AIC6OT3GF",
    ] {
        assert_eq!(text(same).ok().as_deref(), Some(shown), "{same}");
    }
    assert_eq!(
        text("ZZZZZZ-ZZZZZZ-ZZZZZZ-ZZZZZZ").ok().as_deref(),
        Some("ZZZZZZ-ZZZZZZ-ZZZZZZ-ZZZZZZ")
    );
    assert_eq!(
        text("zzzzzzzzzzzzzzzzzzzzzzzz").ok().as_deref(),
        Some("ZZZZZZ-ZZZZZZ-ZZZZZZ-ZZZZZZ")
    );
    for bad in [
        "",
        "04106105",
        &shown[..shown.len() - 1],
        "041061-050R3G-G28A1C-60T3GFA",
        "U41061-050R3G-G28A1C-60T3GF",
        "u41061-050R3G-G28A1C-60T3GF",
        "041061-050R3G-G28A1C-60T3G_",
        "041061-050R3G-G28A1C-60T3Gé",
        "041061-050R3G-G28A1C-60T3G\u{0}",
    ] {
        assert_eq!(
            kind(RecoveryCode::parse(bad)),
            Some(ErrorKind::Malformed),
            "{bad:?}"
        );
    }
    // up to 64 bytes are read, and separators count toward them
    let padded = |n: usize| format!("{}{}", "0".repeat(24), "-".repeat(n - 24));
    assert_eq!(kind(RecoveryCode::parse(&padded(64))), None);
    assert_eq!(
        kind(RecoveryCode::parse(&padded(65))),
        Some(ErrorKind::TooLarge)
    );
    assert_eq!(
        kind(RecoveryCode::parse(&"!".repeat(65))),
        Some(ErrorKind::TooLarge)
    );
    Ok(())
}

fn row(store: &mut Mem, code: &RecoveryCode) -> Option<Row<RecoveryHash>> {
    let row = stored(store, code.key())?;
    match row.record() {
        Record::Recovery(h) => Some(Row::new(*h, row.version())),
        _ => None,
    }
}

#[test]
fn each_code_is_consumed_once() -> Result<(), Boxed> {
    let (mut store, mut e, now) = (Mem::new(), testkit::seeded(11), UnixTime::new(50));
    let pending = recovery_generate(count(3)?, &mut e)?;
    let receipt = applied(&mut store, pending.effect(), now).ok_or("apply")?;
    let codes = pending.settle(receipt)?;
    let [a, b, c] = codes.as_slice() else {
        return Err("three codes".into());
    };
    let verify = |store: &mut Mem,
                  e: &mut testkit::Seeded,
                  code: &RecoveryCode|
     -> Result<Result<(), Rejected>, Boxed> {
        let counted = stored(store, Key::Attempts);
        let attempts = counted.as_ref().and_then(|r| match r.record() {
            Record::Attempts(a) => Some(Row::new(a, r.version())),
            _ => None,
        });
        let permit = Throttle::unlimited()
            .check(attempts, now)
            .map_err(|_| "permit")?;
        let read = row(store, code);
        let seen = read.as_ref().map(|r| Row::new(r.record(), r.version()));
        let pending = recovery_verify(permit, code, seen, e)?;
        let receipt = applied(store, pending.effect(), now).ok_or("apply verdict")?;
        Ok(pending.settle(receipt)?.map(drop))
    };
    // a code reads back as the code it was shown as, and finds its row
    let shown = RecoveryCode::parse(&b.display().to_string())?;
    assert_eq!(verify(&mut store, &mut e, &shown)?, Ok(()));
    assert!(row(&mut store, b).is_none());
    assert!(row(&mut store, a).is_some() && row(&mut store, c).is_some());
    // the second use finds nothing, is Wrong, and still counts
    assert_eq!(verify(&mut store, &mut e, b)?, Err(Rejected::Wrong));
    assert!(row(&mut store, a).is_some() && row(&mut store, c).is_some());
    let attempts = stored(&mut store, Key::Attempts).ok_or("attempts")?;
    assert_eq!(
        Some(attempts.record().clone()),
        Record::decode(&[&[1, 0, 0, 0, 0, 2][..], &now.secs().to_be_bytes()].concat()).ok()
    );
    assert_eq!(verify(&mut store, &mut e, a)?, Ok(()));
    assert_eq!(verify(&mut store, &mut e, c)?, Ok(()));
    Ok(())
}

#[test]
fn a_row_holding_another_digest_is_not_a_match() -> Result<(), Boxed> {
    let mut e = testkit::seeded(12);
    let (mut store, now) = (Mem::new(), UnixTime::new(1));
    let pending = recovery_generate(count(2)?, &mut e)?;
    let receipt = applied(&mut store, pending.effect(), now).ok_or("apply")?;
    let codes = pending.settle(receipt)?;
    let [a, b] = codes.as_slice() else {
        return Err("two codes".into());
    };
    let (under_a, under_b) = (
        row(&mut store, a).ok_or("row")?,
        row(&mut store, b).ok_or("row")?,
    );
    let permit = Throttle::unlimited()
        .check(None, now)
        .map_err(|_| "permit")?;
    let seen = Row::new(under_b.record(), under_a.version());
    let pending = recovery_verify(permit, a, Some(seen), &mut e)?;
    let receipt = applied(&mut store, pending.effect(), now).ok_or("apply")?;
    assert_eq!(pending.settle(receipt)?.map(drop), Err(Rejected::Wrong));
    assert!(row(&mut store, a).is_some() && row(&mut store, b).is_some());
    Ok(())
}

#[test]
fn debug_names_the_type_only() -> Result<(), Boxed> {
    assert_eq!(
        format!("{:?}", RecoveryCode::parse(&"1".repeat(24))?),
        "RecoveryCode { .. }"
    );
    Ok(())
}
