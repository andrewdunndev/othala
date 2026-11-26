//! Relying-party identity and fixed policy: RP ID, origins, cross-origin, counter and trust policies (R8, R9, R19).
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use crate::error::{Error, ErrorKind};
use crate::options::DisplayName;
use crate::{MAX_ORIGINS, MAX_RP_ID};

/// A relying party identifier: a lowercase ASCII domain of at most `MAX_RP_ID` bytes, validated.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RpId(pub(crate) String);

/// A serialized web origin (`https://host[:port]`, or `http://localhost[:port]`) or an `android:apk-key-hash:` origin, compared exactly.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Origin(pub(crate) String);

/// What a signature counter that did not advance means.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CounterPolicy {
    /// The assertion fails with `CounterRegressed`.
    Reject,
    /// The assertion succeeds and reports `Counter::Regressed`.
    Tolerate,
}

/// Whether a ceremony may run in a cross-origin iframe (L3 7.1 steps 10-11, 7.2 steps 13-14).
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrossOrigin {
    /// `crossOrigin: true` and any `topOrigin` fail.
    Deny,
    /// Cross-origin is allowed under any top origin, or none reported.
    AnyTop,
    /// Cross-origin is allowed only with a reported `topOrigin` in this list.
    Listed(Vec<Origin>),
}

/// What an extension output the ceremony did not request means.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnsolicitedExtensions {
    /// The ceremony fails with `Extension`.
    Reject,
    /// The output is ignored.
    Ignore,
}

/// Whether a registration needs attestation that chains to a trust anchor (L3 7.1 step 24).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustPolicy {
    /// None, self and unanchored attestation fail with `Untrusted`.
    RequireTrusted,
    /// Every verified attestation registers; `Registered` reports how far it was trusted.
    AcceptUntrusted,
}

/// Which android-key authorization lists may carry origin and purpose (L3 8.4.1).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyEnforcement {
    /// Only `teeEnforced`.
    TrustedEnvironment,
    /// The union of `teeEnforced` and `softwareEnforced`.
    AnyList,
}

/// One relying party's fixed policy: RP ID, origins and every ceremony option that is not per call.
#[derive(Clone)]
pub struct RelyingParty {
    pub(crate) id: RpId,
    pub(crate) name: DisplayName,
    pub(crate) origins: Vec<Origin>,
    pub(crate) counter: CounterPolicy,
    pub(crate) cross_origin: CrossOrigin,
    pub(crate) unsolicited: UnsolicitedExtensions,
    pub(crate) trust: TrustPolicy,
    pub(crate) android_key: KeyEnforcement,
}

/// Builds a [`RelyingParty`]; cross-origin, unsolicited extensions and untrusted Android lists are off unless set, and unanchored attestation registers unless `TrustPolicy::RequireTrusted` is set.
#[must_use]
#[derive(Clone)]
pub struct RelyingPartyBuilder(pub(crate) RelyingParty);

// lowercase LDH labels, no trailing dot, no IP literal; past `MAX_RP_ID` bytes is `TooLarge`
fn host(text: &str) -> Result<(), Error> {
    if text.len() > MAX_RP_ID {
        return Err(Error::new(ErrorKind::TooLarge));
    }
    let label = |l: &str| {
        (1..=63).contains(&l.len())
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let numeric_tld = text
        .rsplit('.')
        .next()
        .is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    if text.split('.').all(label) && !numeric_tld {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::Malformed))
    }
}

impl RpId {
    /// Parse an RP ID; anything but a lowercase ASCII domain is `Malformed`, past `MAX_RP_ID` is `TooLarge`.
    pub fn parse(text: &str) -> Result<Self, Error> {
        host(text).map(|()| Self(text.to_string()))
    }

    /// The RP ID as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Origin {
    /// Parse an origin in the form a client serializes it; any other spelling is `Malformed`.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let malformed = Error::new(ErrorKind::Malformed);
        if let Some(hash) = text.strip_prefix("android:apk-key-hash:") {
            let symbols = hash
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            return if hash.len() == 43 && symbols {
                Ok(Self(text.to_string()))
            } else {
                Err(malformed)
            };
        }
        let (default, rest) = match (text.strip_prefix("https://"), text.strip_prefix("http://")) {
            (Some(rest), _) => (443, rest),
            (_, Some(rest)) => (80, rest),
            _ => return Err(malformed),
        };
        let (name, port) = rest
            .split_once(':')
            .map_or((rest, None), |(n, p)| (n, Some(p)));
        host(name)?;
        if default == 80 && name != "localhost" {
            return Err(malformed);
        }
        if let Some(port) = port {
            let digits = port.bytes().all(|b| b.is_ascii_digit()) && !port.starts_with('0');
            match port.parse::<u16>() {
                Ok(n) if digits && n != default => {}
                _ => return Err(malformed),
            }
        }
        Ok(Self(text.to_string()))
    }

    /// The origin as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl RelyingParty {
    /// Start from the RP ID, its display name, its first origin and the counter policy.
    pub fn builder(
        id: RpId,
        name: DisplayName,
        origin: Origin,
        counter: CounterPolicy,
    ) -> RelyingPartyBuilder {
        RelyingPartyBuilder(Self {
            id,
            name,
            origins: alloc::vec![origin],
            counter,
            cross_origin: CrossOrigin::Deny,
            unsolicited: UnsolicitedExtensions::Reject,
            trust: TrustPolicy::AcceptUntrusted,
            android_key: KeyEnforcement::TrustedEnvironment,
        })
    }

    /// The RP ID every ceremony hashes.
    pub fn id(&self) -> &RpId {
        &self.id
    }
}

impl RelyingPartyBuilder {
    /// Accept one more origin.
    pub fn origin(mut self, origin: Origin) -> Self {
        self.0.origins.push(origin);
        self
    }

    /// Set the cross-origin policy; the default is `CrossOrigin::Deny`.
    pub fn cross_origin(mut self, policy: CrossOrigin) -> Self {
        self.0.cross_origin = policy;
        self
    }

    /// Set the unsolicited-extension policy; the default is `UnsolicitedExtensions::Reject`.
    pub fn unsolicited(mut self, policy: UnsolicitedExtensions) -> Self {
        self.0.unsolicited = policy;
        self
    }

    /// Set the attestation trust policy; the default is `TrustPolicy::AcceptUntrusted`, since most ceremonies convey no attestation, and a `TrustDecision::Denied` fails under either.
    pub fn trust(mut self, policy: TrustPolicy) -> Self {
        self.0.trust = policy;
        self
    }

    /// Set the android-key list policy; the default is `KeyEnforcement::TrustedEnvironment`.
    pub fn android_key(mut self, policy: KeyEnforcement) -> Self {
        self.0.android_key = policy;
        self
    }

    /// Finish; a repeated origin is `Malformed`, more than `MAX_ORIGINS` is `TooLarge`.
    pub fn build(self) -> Result<RelyingParty, Error> {
        let rp = self.0;
        if rp
            .origins
            .iter()
            .enumerate()
            .any(|(i, o)| rp.origins.iter().skip(i + 1).any(|p| p == o))
        {
            return Err(Error::new(ErrorKind::Malformed));
        }
        let tops = match &rp.cross_origin {
            CrossOrigin::Listed(tops) => tops.len(),
            _ => 0,
        };
        if rp.origins.len() + tops > MAX_ORIGINS {
            return Err(Error::new(ErrorKind::TooLarge));
        }
        Ok(rp)
    }
}

impl fmt::Debug for RelyingParty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelyingParty")
            .field("id", &self.id)
            .field("origins", &self.origins)
            .field("counter", &self.counter)
            .field("cross_origin", &self.cross_origin)
            .field("unsolicited", &self.unsolicited)
            .field("trust", &self.trust)
            .field("android_key", &self.android_key)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for RelyingPartyBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RelyingPartyBuilder").field(&self.0).finish()
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::{String, ToString};
    use alloc::vec;

    use super::{
        CounterPolicy, CrossOrigin, KeyEnforcement, Origin, RelyingParty, RpId, TrustPolicy,
        UnsolicitedExtensions,
    };
    use crate::error::ErrorKind;
    use crate::options::DisplayName;
    use crate::{MAX_ORIGINS, MAX_RP_ID};

    fn origin(text: &str) -> Origin {
        Origin(text.to_string())
    }

    fn kind<T>(r: Result<T, crate::error::Error>) -> Option<ErrorKind> {
        r.err().map(|e| e.kind())
    }

    #[test]
    fn rp_ids_are_lowercase_domains() {
        for good in [
            "example.org",
            "localhost",
            "a-b.c1.example",
            "xn--bcher-kva.example",
            "a",
            "a.b",
        ] {
            assert_eq!(RpId::parse(good).as_ref().map(RpId::as_str), Ok(good));
        }
        for bad in [
            "",
            "Example.org",
            "example.org.",
            ".example",
            "a..b",
            "-a.org",
            "a-.org",
            "a_b.org",
            "127.0.0.1",
            "1",
            "[::1]",
            "a b",
            "example.org:8443",
            "ex\u{e9}.org",
            &"a".repeat(64),
        ] {
            assert_eq!(kind(RpId::parse(bad)), Some(ErrorKind::Malformed), "{bad}");
        }
        let long = |n: usize| {
            [
                "a".repeat(63),
                "a".repeat(63),
                "a".repeat(63),
                "a".repeat(n - 192),
            ]
            .join(".")
        };
        assert!(RpId::parse(&long(MAX_RP_ID)).is_ok());
        assert_eq!(
            kind(RpId::parse(&long(MAX_RP_ID + 1))),
            Some(ErrorKind::TooLarge)
        );
    }

    #[test]
    fn origins_are_serialized_as_a_client_sends_them() {
        let key = "A".repeat(43);
        for good in [
            "https://example.org",
            "https://example.org:8443",
            "http://localhost",
            "http://localhost:3000",
            "https://localhost",
            "https://65535.example:65535",
        ] {
            assert_eq!(Origin::parse(good).as_ref().map(Origin::as_str), Ok(good));
        }
        for hash in [
            key.clone(),
            format!("{}-_", &key[2..]),
            format!("_{}", &key[1..]),
        ] {
            let android = format!("android:apk-key-hash:{hash}");
            assert_eq!(Origin::parse(&android).map(|o| o.0), Ok(android));
        }
        for bad in [
            "",
            "example.org",
            "https://",
            "https://example.org/",
            "https://example.org/x",
            "https://example.org?x",
            "https://example.org#x",
            "https://u@example.org",
            "https://Example.org",
            "http://example.org",
            "http://localhost.example",
            "ftp://example.org",
            "https://example.org:443",
            "http://localhost:80",
            "https://example.org:0",
            "https://example.org:08443",
            "https://example.org:65536",
            "https://example.org:",
            "https://example.org:84a3",
            "https://example.org:+443",
            "https://127.0.0.1",
            "https://[::1]",
            "https://example.org.",
            "wss://example.org",
            "HTTPS://example.org",
            "android:apk-key-hash:",
            "android:apk-key-hash:A",
            "android:apk-key-hash:A=",
            "android:apk-key-hash:+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert_eq!(
                kind(Origin::parse(bad)),
                Some(ErrorKind::Malformed),
                "{bad}"
            );
        }
        assert_eq!(
            kind(Origin::parse(&format!("android:apk-key-hash:{key}A"))),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            kind(Origin::parse(&format!(
                "https://{}",
                "a".repeat(MAX_RP_ID + 1)
            ))),
            Some(ErrorKind::TooLarge)
        );
    }

    #[test]
    fn the_builder_defaults_and_bounds() {
        let builder = |extra: usize| {
            let name = DisplayName(String::new());
            let mut b = RelyingParty::builder(
                RpId("a.example".into()),
                name,
                origin("https://a0.example"),
                CounterPolicy::Reject,
            );
            for i in 1..=extra {
                b = b.origin(origin(&format!("https://a{i}.example")));
            }
            b
        };
        let rp = builder(1).build();
        assert_eq!(rp.as_ref().map(|r| r.id().as_str()), Ok("a.example"));
        assert_eq!(rp.as_ref().map(|r| r.origins.len()), Ok(2));
        assert_eq!(
            rp.as_ref()
                .map(|r| (r.counter, r.unsolicited, r.trust, r.android_key)),
            Ok((
                CounterPolicy::Reject,
                UnsolicitedExtensions::Reject,
                TrustPolicy::AcceptUntrusted,
                KeyEnforcement::TrustedEnvironment
            ))
        );
        assert_eq!(rp.map(|r| r.cross_origin), Ok(CrossOrigin::Deny));
        let set = builder(0)
            .cross_origin(CrossOrigin::AnyTop)
            .unsolicited(UnsolicitedExtensions::Ignore)
            .trust(TrustPolicy::RequireTrusted)
            .android_key(KeyEnforcement::AnyList)
            .build();
        assert_eq!(
            set.as_ref()
                .map(|r| (r.unsolicited, r.trust, r.android_key)),
            Ok((
                UnsolicitedExtensions::Ignore,
                TrustPolicy::RequireTrusted,
                KeyEnforcement::AnyList
            ))
        );
        assert_eq!(set.map(|r| r.cross_origin), Ok(CrossOrigin::AnyTop));
        assert!(builder(MAX_ORIGINS - 1).build().is_ok());
        assert_eq!(
            kind(builder(MAX_ORIGINS).build()),
            Some(ErrorKind::TooLarge)
        );
        assert_eq!(
            kind(builder(0).origin(origin("https://a0.example")).build()),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            kind(builder(1).origin(origin("https://a1.example")).build()),
            Some(ErrorKind::Malformed)
        );
        let tops = |n: usize| CrossOrigin::Listed(vec![origin("https://top.example"); n]);
        assert!(
            builder(0)
                .cross_origin(tops(MAX_ORIGINS - 1))
                .build()
                .is_ok()
        );
        assert_eq!(
            kind(builder(0).cross_origin(tops(MAX_ORIGINS)).build()),
            Some(ErrorKind::TooLarge)
        );
        let debug = format!("{:?}", builder(0));
        assert!(
            debug.starts_with("RelyingPartyBuilder(RelyingParty")
                && debug.contains("a.example")
                && !debug.contains("name")
        );
    }
}
