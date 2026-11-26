use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use base::{Entropy, Row, SecretBytes, UnixTime};
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::{Effect, Error, ErrorKind, Key, Pending, Permit, Record, Rejected};

const MAX_CODE: usize = 16;

/// The HMAC hash of an authenticator.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OtpAlg {
    /// HMAC-SHA-1, the RFC 4226 and RFC 6238 default.
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

/// The number of decimal digits in a code.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Digits {
    /// Six digits.
    Six,
    /// Eight digits.
    Eight,
}

/// The TOTP time step: 15 to 300 seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Period(u32);

/// How many steps either side of the current one are accepted.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Skew {
    /// The current step only.
    Exact,
    /// One step before or after.
    One,
}

/// An authenticator's shared secret: 16 to 64 bytes, wiped on drop by base.
pub struct OtpKey(SecretBytes);

impl OtpKey {
    /// Accepts 16 to 64 bytes (RFC 4226 R6); the bytes are wiped on any refusal too.
    pub fn import(key: Vec<u8>) -> Result<Self, Error> {
        let len = key.len();
        let secret = SecretBytes::new(key);
        match len {
            16..=64 => Ok(Self(secret)),
            0..16 => Err(Error {
                kind: ErrorKind::WeakKey,
            }),
            _ => Err(Error {
                kind: ErrorKind::TooLarge,
            }),
        }
    }
}

fn mac<M: Mac + KeyInit>(key: &[u8], counter: u64) -> Option<Zeroizing<Vec<u8>>> {
    let mut mac = <M as KeyInit>::new_from_slice(key).ok()?;
    mac.update(&counter.to_be_bytes());
    let mut out = mac.finalize().into_bytes();
    let tag = Zeroizing::new(out.to_vec());
    out.as_mut_slice().zeroize();
    Some(tag)
}

/// RFC 4226 5.3: HMAC of the counter, dynamic truncation, modulo `10^digits`.
pub(crate) fn hotp(key: &OtpKey, alg: OtpAlg, counter: u64, digits: Digits) -> u32 {
    let key = key.0.expose();
    let tag = match alg {
        OtpAlg::Sha1 => mac::<Hmac<Sha1>>(key, counter),
        OtpAlg::Sha256 => mac::<Hmac<Sha256>>(key, counter),
        OtpAlg::Sha512 => mac::<Hmac<Sha512>>(key, counter),
    };
    let word = tag.as_ref().and_then(|t| {
        let offset = usize::from(t.last()? & 0x0f);
        let bytes = t.get(offset..)?.first_chunk::<4>()?;
        Some(u32::from_be_bytes(*bytes) & 0x7fff_ffff)
    });
    word.unwrap_or(0)
        % match digits {
            Digits::Six => 1_000_000,
            Digits::Eight => 100_000_000,
        }
}

impl OtpKey {
    /// 20, 32 or 64 random bytes for SHA-1, SHA-256 or SHA-512, the HMAC's own block-matched strengths.
    pub fn generate(alg: OtpAlg, e: &mut impl Entropy) -> Self {
        let mut key = vec![
            0;
            match alg {
                OtpAlg::Sha1 => 20,
                OtpAlg::Sha256 => 32,
                OtpAlg::Sha512 => 64,
            }
        ];
        e.fill(&mut key);
        Self(SecretBytes::new(key))
    }

    /// The key byte for byte, for the host to store encrypted.
    pub fn export(&self) -> SecretBytes {
        SecretBytes::new(self.0.expose().to_vec())
    }
}

impl fmt::Debug for OtpKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtpKey").finish_non_exhaustive()
    }
}

impl Period {
    /// Accepts 15 to 300 seconds.
    pub const fn new(secs: u32) -> Result<Self, Error> {
        match secs {
            15..=300 => Ok(Self(secs)),
            _ => Err(Error {
                kind: ErrorKind::OutOfRange,
            }),
        }
    }
}

/// An RFC 6238 authenticator with T0 at the epoch; the host stores it, and its last step is a row of its own.
pub struct Totp {
    key: OtpKey,
    alg: OtpAlg,
    digits: Digits,
    period: Period,
    skew: Skew,
}

/// The last step an authenticator accepted; stored under [`crate::Key::TotpStep`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TotpStep(u64);

impl TotpStep {
    pub(crate) const fn new(step: u64) -> Self {
        Self(step)
    }

    pub(crate) const fn parts(&self) -> u64 {
        self.0
    }
}

/// A code as presented: six or eight ASCII digits, wiped on drop by base.
pub struct OtpCode(SecretBytes);

impl OtpCode {
    /// Six or eight ASCII digits; `TooLarge` over 16 bytes is read first.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let kind = if text.len() > MAX_CODE {
            ErrorKind::TooLarge
        } else if matches!(text.len(), 6 | 8) && text.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(Self(SecretBytes::new(text.as_bytes().to_vec())));
        } else {
            ErrorKind::Malformed
        };
        Err(Error { kind })
    }
}

impl fmt::Debug for OtpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtpCode").finish_non_exhaustive()
    }
}

/// A code matched a step after the last one accepted.
#[derive(Debug)]
pub struct OtpMatch {
    step: TotpStep,
}

impl OtpMatch {
    /// The step the code matched, which the host's stored step now holds.
    pub const fn step(&self) -> u64 {
        self.step.parts()
    }
}

impl fmt::Debug for Totp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Totp").finish_non_exhaustive()
    }
}

impl Totp {
    /// An authenticator over `key`; the host stores it and its parameters.
    pub const fn new(key: OtpKey, alg: OtpAlg, digits: Digits, period: Period, skew: Skew) -> Self {
        Self {
            key,
            alg,
            digits,
            period,
            skew,
        }
    }

    /// The code's digits for `step`, zero-padded, in the front of the array.
    fn text(&self, step: u64) -> (Zeroizing<[u8; 8]>, usize) {
        let width = match self.digits {
            Digits::Six => 6,
            Digits::Eight => 8,
        };
        let mut value = hotp(&self.key, self.alg, step, self.digits);
        let mut text = Zeroizing::new([b'0'; 8]);
        for slot in text.iter_mut().take(width).rev() {
            *slot = b'0' + u8::try_from(value % 10).unwrap_or_default();
            value /= 10;
        }
        (text, width)
    }

    /// The earliest candidate step after `last` that `code` matches; every candidate is compared, in constant time.
    fn find(&self, code: &OtpCode, now: UnixTime, last: Option<u64>) -> Result<u64, Rejected> {
        let at = now.secs() / u64::from(self.period.0);
        let span = match self.skew {
            Skew::Exact => 0,
            Skew::One => 1,
        };
        let (mut fresh, mut stale) = (None, false);
        for step in at.saturating_sub(span)..=at.saturating_add(span) {
            let (text, width) = self.text(step);
            let hit = text
                .get(..width)
                .is_some_and(|t| bool::from(t.ct_eq(code.0.expose())));
            match (hit, last.is_some_and(|l| step <= l)) {
                (true, true) => stale = true,
                (true, false) => fresh = fresh.or(Some(step)),
                (false, _) => {}
            }
        }
        match (fresh, stale) {
            (Some(step), _) => Ok(step),
            (None, true) => Err(Rejected::Replayed),
            (None, false) => Err(Rejected::Wrong),
        }
    }

    /// The verdict at the permit's time, with the effect that counts it and moves or guards the stored step.
    pub fn verify(
        &self,
        permit: Permit,
        code: &OtpCode,
        last: Option<Row<&TotpStep>>,
        e: &mut impl Entropy,
    ) -> Result<Pending<Result<OtpMatch, Rejected>>, Error> {
        let verdict = self.find(
            code,
            permit.time(),
            last.as_ref().map(|r| r.record().parts()),
        );
        let counted = permit.count(e);
        let put = |step| Record::TotpStep(TotpStep::new(step));
        let effect = match (&verdict, &last) {
            (Ok(step), Some(row)) => counted.update(Key::TotpStep, row, put(*step), None),
            (Ok(step), None) => counted.create(Key::TotpStep, put(*step), None),
            (Err(_), Some(row)) => counted.expect(Key::TotpStep, row),
            (Err(_), None) => counted.expect_absent(Key::TotpStep),
        }
        .build()
        .map_err(|_| Error {
            kind: ErrorKind::Internal,
        })?;
        let step = |step| OtpMatch {
            step: TotpStep::new(step),
        };
        Ok(Pending::new(verdict.map(step), effect))
    }

    /// Matches `code` at `now` as `verify` would and returns an uncounted effect recording the step.
    pub fn confirm(
        &self,
        code: &OtpCode,
        now: UnixTime,
        last: Option<Row<&TotpStep>>,
        e: &mut impl Entropy,
    ) -> Result<Effect, Rejected> {
        let step = self.find(code, now, last.as_ref().map(|r| r.record().parts()))?;
        let record = Record::TotpStep(TotpStep::new(step));
        Ok(match last {
            Some(row) => Effect::updated(e, Key::TotpStep, &row, record, None),
            None => Effect::created(e, Key::TotpStep, record, None),
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{OtpAlg, OtpKey};
    use crate::ErrorKind;

    #[test]
    fn generate_draws_the_hash_size_and_export_returns_it() {
        let mut e = testkit::seeded(5);
        for (alg, len) in [
            (OtpAlg::Sha1, 20),
            (OtpAlg::Sha256, 32),
            (OtpAlg::Sha512, 64),
        ] {
            let key = OtpKey::generate(alg, &mut e);
            assert_eq!(key.export().expose(), key.0.expose());
            assert_eq!(key.0.expose().len(), len);
            assert!(key.0.expose().iter().any(|b| *b != 0));
        }
    }

    #[test]
    fn key_bounds() {
        let kind = |n: usize| OtpKey::import(vec![7; n]).err().map(|e| e.kind());
        assert_eq!(kind(0), Some(ErrorKind::WeakKey));
        assert_eq!(kind(15), Some(ErrorKind::WeakKey));
        assert_eq!(kind(16), None);
        assert_eq!(kind(64), None);
        assert_eq!(kind(65), Some(ErrorKind::TooLarge));
    }
}

#[cfg(test)]
mod rfc4226 {
    use alloc::string::String;
    use serde::Deserialize;
    use testkit::vectors::{Outcome, run};

    use super::{Digits, OtpAlg, OtpKey, hotp};
    use crate::tests::unhex;

    #[derive(Deserialize)]
    struct Appendix {
        secret: String,
        counter: u64,
        digits: u8,
        expect: Out,
    }

    #[derive(Deserialize)]
    struct Out {
        out: String,
    }

    #[derive(Deserialize)]
    struct Derived {
        op: String,
        secret: String,
        digits: u8,
        code: Option<String>,
        expect: Verdict,
    }

    #[derive(Deserialize)]
    struct Verdict {
        ok: bool,
        next_counter: Option<u64>,
    }

    fn digits(n: u8) -> Option<Digits> {
        match n {
            6 => Some(Digits::Six),
            8 => Some(Digits::Eight),
            _ => None,
        }
    }

    fn code(secret: &str, counter: u64, n: u8) -> Option<String> {
        let key = OtpKey::import(unhex(secret)?).ok()?;
        let width = usize::from(n);
        Some(alloc::format!(
            "{:0width$}",
            hotp(&key, OtpAlg::Sha1, counter, digits(n)?)
        ))
    }

    #[test]
    fn appendix_d() {
        let tally = run(testkit::vector!("rfc4226/hotp.json"), 10, |c: &Appendix| {
            let got = code(&c.secret, c.counter, c.digits);
            assert_eq!(got.as_deref(), Some(c.expect.out.as_str()));
            Outcome::Checked
        });
        assert_eq!(tally.checked(), tally.total());
    }

    // look-ahead and resynchronization need a stored counter, which is not here (R-k): a match names only its counter's value
    #[test]
    fn derived_values() {
        let tally = run(
            testkit::vector!("factor-derived/hotp.json"),
            3,
            |c: &Derived| {
                let named = c.op == "hotp_verify" && c.expect.ok;
                let Some(next) = c.expect.next_counter.filter(|_| named) else {
                    return Outcome::NotApplicable;
                };
                let got = code(&c.secret, next.saturating_sub(1), c.digits);
                assert_eq!(got, c.code);
                Outcome::Checked
            },
        );
        assert_eq!(tally.checked(), 3);
    }
}
