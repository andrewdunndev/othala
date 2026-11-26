//! Row m3-factor-rfc6238: RFC 6238 appendix B through `Totp::verify`, and the claims about parsing, windows and `confirm`.
mod common;

use base::{Row, UnixTime};
use common::{Case, Mem, Outcome, applied, attempts, last, run, step_record, stored, totp};
use factor::{ErrorKind, Key, OtpCode, OtpKey, Period, Rejected, Throttle};
use testkit::vectors::{Outcome as Seen, run as run_vector};
use testkit::{seeded, vector};

fn kind<T>(r: Result<T, factor::Error>) -> Option<ErrorKind> {
    r.err().map(|e| e.kind())
}

#[test]
fn appendix_b() {
    let tally = run_vector(vector!("rfc6238/totp.json"), 45, |c: &Case| {
        let Some((outcome, mut store)) = run(c) else {
            return Seen::NotApplicable;
        };
        let accepted = matches!(outcome, Outcome::Verdict(Ok(_)));
        assert_eq!(accepted, c.expect.ok, "{}", c.id);
        // every verdict counts once, and only a match moves the step
        assert!(attempts(&mut store).is_some(), "{}", c.id);
        assert_eq!(
            last(&mut store).is_some(),
            accepted || c.last_step.is_some(),
            "{}",
            c.id
        );
        Seen::Checked
    });
    assert_eq!(tally.checked(), tally.total());
}

#[test]
fn period_bounds() {
    assert_eq!(kind(Period::new(14)), Some(ErrorKind::OutOfRange));
    assert_eq!(kind(Period::new(15)), None);
    assert_eq!(kind(Period::new(300)), None);
    assert_eq!(kind(Period::new(301)), Some(ErrorKind::OutOfRange));
}

#[test]
fn code_text() {
    for ok in ["000000", "12345678", "00000000"] {
        assert_eq!(kind(OtpCode::parse(ok)), None, "{ok}");
    }
    for bad in [
        "",
        "12345",
        "1234567",
        "123456789",
        "12345a",
        " 123456",
        "１２３４",
        "-12345",
        "1234 56",
    ] {
        assert_eq!(
            kind(OtpCode::parse(bad)),
            Some(ErrorKind::Malformed),
            "{bad}"
        );
    }
    // the size bound is read before the digits
    assert_eq!(
        kind(OtpCode::parse(&"9".repeat(16))),
        Some(ErrorKind::Malformed)
    );
    assert_eq!(
        kind(OtpCode::parse(&"9".repeat(17))),
        Some(ErrorKind::TooLarge)
    );
    assert_eq!(
        kind(OtpCode::parse(&"x".repeat(17))),
        Some(ErrorKind::TooLarge)
    );
}

fn sha1_case(digits: u8, window: u8, time: u64, code: &str) -> Case {
    let secret = "3132333435363738393031323334353637383930".to_string();
    let expect = common::Expect {
        ok: true,
        step: None,
        kind: None,
    };
    Case {
        id: code.into(),
        secret,
        alg: "sha1".into(),
        digits,
        step: 30,
        time,
        window,
        last_step: None,
        code: code.into(),
        expect,
    }
}

#[test]
fn window_edges_and_length() {
    // appendix B: 94287082 is the SHA-1 code of the step starting at time 30
    let accepts = |c: &Case| matches!(run(c), Some((Outcome::Verdict(Ok(_)), _)));
    assert!(
        accepts(&sha1_case(8, 1, 29, "94287082")),
        "step 1 is one ahead of step 0, and T - 1 saturates at 0"
    );
    assert!(!accepts(&sha1_case(8, 0, 29, "94287082")));
    assert!(
        accepts(&sha1_case(6, 1, 59, "287082")),
        "the same value modulo 10^6"
    );
    assert!(
        !accepts(&sha1_case(8, 1, 59, "287082")),
        "six digits for an eight-digit authenticator"
    );
    assert!(!accepts(&sha1_case(8, 1, u64::MAX, "94287082")));
}

#[test]
fn confirm_records_the_step_and_bars_its_own_code() -> Result<(), Box<dyn std::error::Error>> {
    let c = sha1_case(8, 1, 59, "94287082");
    let (mut store, mut e) = (Mem::new(), seeded(2));
    let t = totp(&c).ok_or("totp")?;
    let code = OtpCode::parse(&c.code)?;
    let now = UnixTime::new(c.time);
    let effect = t.confirm(&code, now, None, &mut e).map_err(|_| "confirm")?;
    assert!(
        effect.guards().all(|g| **g.key() == Key::TotpStep),
        "uncounted"
    );
    applied(&mut store, &effect, now).ok_or("apply")?;
    assert!(stored(&mut store, Key::Attempts).is_none());
    let row = last(&mut store).ok_or("step row")?;
    assert_eq!(
        stored(&mut store, Key::TotpStep).map(|r| r.record().clone()),
        step_record(1)
    );
    // the same code at the first login is a replay
    let permit = Throttle::unlimited()
        .check(None, now)
        .map_err(|_| "permit")?;
    let seen = Row::new(row.record(), row.version());
    let verdict = t.verify(permit, &code, Some(seen.clone()), &mut e)?;
    let receipt = applied(&mut store, verdict.effect(), now).ok_or("apply")?;
    assert!(matches!(verdict.settle(receipt)?, Err(Rejected::Replayed)));
    // and confirm itself refuses a step at or before the last
    assert!(matches!(
        t.confirm(&code, now, Some(seen), &mut e),
        Err(Rejected::Replayed)
    ));
    Ok(())
}

#[test]
fn debug_names_the_type_only() -> Result<(), Box<dyn std::error::Error>> {
    let c = sha1_case(8, 1, 59, "94287082");
    assert_eq!(format!("{:?}", totp(&c).ok_or("totp")?), "Totp { .. }");
    assert_eq!(format!("{:?}", OtpCode::parse("123456")?), "OtpCode { .. }");
    assert_eq!(
        format!("{:?}", OtpKey::import(vec![1; 16])?),
        "OtpKey { .. }"
    );
    Ok(())
}
