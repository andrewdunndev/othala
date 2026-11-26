#![expect(
    dead_code,
    reason = "fields are read by the bodies factor-02 and factor-06 land"
)]

use alloc::vec::Vec;

use base::SecretBytes;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::{Error, ErrorKind};

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

fn mac<M: Mac + KeyInit>(key: &[u8], counter: u64) -> Option<Vec<u8>> {
    let mut mac = <M as KeyInit>::new_from_slice(key).ok()?;
    mac.update(&counter.to_be_bytes());
    Some(mac.finalize().into_bytes().to_vec())
}

/// RFC 4226 5.3: HMAC of the counter, dynamic truncation, modulo `10^digits`.
pub(crate) fn hotp(key: &OtpKey, alg: OtpAlg, counter: u64, digits: Digits) -> u32 {
    let key = key.0.expose();
    let tag = match alg {
        OtpAlg::Sha1 => mac::<Hmac<Sha1>>(key, counter),
        OtpAlg::Sha256 => mac::<Hmac<Sha256>>(key, counter),
        OtpAlg::Sha512 => mac::<Hmac<Sha512>>(key, counter),
    };
    let word = tag.as_deref().and_then(|t| {
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

/// A code as presented: six or eight ASCII digits, wiped on drop by base.
pub struct OtpCode(SecretBytes);

/// A code matched a step after the last one accepted.
#[derive(Debug)]
pub struct OtpMatch {
    step: TotpStep,
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::OtpKey;
    use crate::ErrorKind;

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
        counter: u64,
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
