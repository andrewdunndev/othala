//! The one error type: a kind plus the ceremony step that raised it (R145, R146).
use core::fmt;

/// The crate's one error type. `Display` names the kind and the spec step, never input bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    step: Option<SpecStep>,
}

/// Why a call failed. Kinds are for logs; a host shows the client one refusal for every ceremony failure (O10).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// Input is not well-formed, or is empty where a value is required: CBOR, JSON, COSE, DER, base64url or a field shape.
    Malformed,
    /// Input or a list exceeds its stated bound.
    TooLarge,
    /// `C.type` is not the ceremony's type.
    Type,
    /// `C.challenge` is not the ceremony's challenge.
    ChallengeMismatch,
    /// `C.origin` is not an origin of the relying party.
    OriginMismatch,
    /// `C.crossOrigin` is true and the relying party does not allow it.
    CrossOriginDenied,
    /// `C.topOrigin` is present and not allowed.
    TopOriginDenied,
    /// `rpIdHash` is not the hash of the RP ID (or of the AppID, when used).
    RpIdHash,
    /// The UP flag is not set where it must be.
    UserNotPresent,
    /// User verification is required and the UV flag is clear.
    UserNotVerified,
    /// BS is set without BE.
    BackupStateWithoutEligibility,
    /// BE differs from the stored credential's.
    BackupEligibilityChanged,
    /// The credential's algorithm was not offered, or is not supported.
    Algorithm,
    /// `fmt` names no supported attestation statement format.
    UnknownFormat,
    /// `fmt` names a format whose cargo feature is off.
    FormatDisabled,
    /// The attestation statement or its certificate chain does not verify.
    AttestationInvalid,
    /// The attestation verified but is not trustworthy: denied by the `TrustSource`, or not anchored under `TrustPolicy::RequireTrusted`.
    Untrusted,
    /// The attested credential id is longer than `MAX_CREDENTIAL_ID` or differs from the response's raw id.
    CredentialIdInvalid,
    /// The credential is not in the ceremony's allow list.
    NotAllowed,
    /// The response's credential id is not the stored credential's.
    CredentialMismatch,
    /// The user handle is missing where required, or names another user.
    UserHandleMismatch,
    /// The finishing browser's binding is not the one the ceremony started with.
    BrowserMismatch,
    /// The assertion signature does not verify.
    Signature,
    /// The signature counter did not advance under `CounterPolicy::Reject`.
    CounterRegressed,
    /// An extension input or output was not requested, or contradicts the request.
    Extension,
    /// The ceremony is at or past its deadline.
    Expired,
    /// A stored record does not decode, or a row is not the record kind its key names.
    Corrupt,
}

/// A ceremony step of L3 section 7, by its number in the Recommendation.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SpecStep {
    /// Section 7.1, registering a new credential.
    Registration(u8),
    /// Section 7.2, verifying an authentication assertion.
    Authentication(u8),
}

impl Error {
    /// What failed.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The L3 7.1 or 7.2 step that failed, when the failure is a ceremony step.
    pub fn spec_step(&self) -> Option<SpecStep> {
        self.step
    }

    pub(crate) const fn new(kind: ErrorKind) -> Self {
        Self { kind, step: None }
    }

    pub(crate) const fn at(kind: ErrorKind, step: SpecStep) -> Self {
        Self {
            kind,
            step: Some(step),
        }
    }
}

impl ErrorKind {
    /// A fixed sentence naming the caller's next action; it holds no input bytes.
    const fn message(self) -> &'static str {
        match self {
            Self::Malformed => {
                "input is not well-formed; reject the request, it cannot be repaired"
            }
            Self::TooLarge => "input exceeds a size bound; reject the request",
            Self::Type => {
                "client data type is not this ceremony's; reject the response and restart the ceremony"
            }
            Self::ChallengeMismatch => {
                "challenge is not this ceremony's; reject the response and restart the ceremony"
            }
            Self::OriginMismatch => {
                "origin is not one of the relying party's; reject the response or add the origin to the relying party"
            }
            Self::CrossOriginDenied => {
                "cross-origin use is not allowed; reject the response or allow it on the relying party"
            }
            Self::TopOriginDenied => {
                "top origin is not allowed; reject the response or allow it on the relying party"
            }
            Self::RpIdHash => {
                "RP ID hash does not match; check that the relying party's id is the one the client used"
            }
            Self::UserNotPresent => {
                "user presence is not asserted; reject the response and ask the user to retry"
            }
            Self::UserNotVerified => {
                "user verification is required but not asserted; reject the response and ask the user to retry with verification"
            }
            Self::BackupStateWithoutEligibility => {
                "backup state is set without backup eligibility; reject the authenticator data as invalid"
            }
            Self::BackupEligibilityChanged => {
                "backup eligibility differs from the stored credential's; reject the response"
            }
            Self::Algorithm => {
                "credential algorithm was not offered or is not supported; offer it or reject the credential"
            }
            Self::UnknownFormat => {
                "attestation format is not supported; reject the credential or request attestation none"
            }
            Self::FormatDisabled => {
                "attestation format's feature is off; enable the feature or reject the credential"
            }
            Self::AttestationInvalid => "attestation does not verify; reject the credential",
            Self::Untrusted => {
                "attestation is not trusted; reject the credential or change the trust policy"
            }
            Self::CredentialIdInvalid => {
                "credential id is too long or differs from the raw id; reject the credential"
            }
            Self::NotAllowed => "credential is not in the allow list; reject the response",
            Self::CredentialMismatch => {
                "credential id is not the stored credential's; look up the stored credential by the response's id"
            }
            Self::UserHandleMismatch => {
                "user handle is missing or names another user; reject the response"
            }
            Self::BrowserMismatch => {
                "browser binding differs from the one the ceremony started with; reject the response and restart the ceremony"
            }
            Self::Signature => "signature does not verify; reject the response",
            Self::CounterRegressed => {
                "signature counter did not advance; treat the credential as possibly cloned or change the counter policy"
            }
            Self::Extension => {
                "extension was not requested or contradicts the request; reject the response"
            }
            Self::Expired => "ceremony has expired; restart the ceremony",
            Self::Corrupt => {
                "stored record does not decode; discard the record and restart the ceremony"
            }
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind.message())?;
        match self.step {
            Some(SpecStep::Registration(n)) => write!(f, " at registration step {n}"),
            Some(SpecStep::Authentication(n)) => write!(f, " at authentication step {n}"),
            None => Ok(()),
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;
    use alloc::format;

    use super::{Error, ErrorKind, SpecStep};

    /// Every kind with its position and exact text; the match has no `_` arm, so a new kind fails to compile here.
    fn row(kind: ErrorKind) -> (usize, &'static str) {
        match kind {
            ErrorKind::Malformed => (
                0,
                "input is not well-formed; reject the request, it cannot be repaired",
            ),
            ErrorKind::TooLarge => (1, "input exceeds a size bound; reject the request"),
            ErrorKind::Type => (
                2,
                "client data type is not this ceremony's; reject the response and restart the ceremony",
            ),
            ErrorKind::ChallengeMismatch => (
                3,
                "challenge is not this ceremony's; reject the response and restart the ceremony",
            ),
            ErrorKind::OriginMismatch => (
                4,
                "origin is not one of the relying party's; reject the response or add the origin to the relying party",
            ),
            ErrorKind::CrossOriginDenied => (
                5,
                "cross-origin use is not allowed; reject the response or allow it on the relying party",
            ),
            ErrorKind::TopOriginDenied => (
                6,
                "top origin is not allowed; reject the response or allow it on the relying party",
            ),
            ErrorKind::RpIdHash => (
                7,
                "RP ID hash does not match; check that the relying party's id is the one the client used",
            ),
            ErrorKind::UserNotPresent => (
                8,
                "user presence is not asserted; reject the response and ask the user to retry",
            ),
            ErrorKind::UserNotVerified => (
                9,
                "user verification is required but not asserted; reject the response and ask the user to retry with verification",
            ),
            ErrorKind::BackupStateWithoutEligibility => (
                10,
                "backup state is set without backup eligibility; reject the authenticator data as invalid",
            ),
            ErrorKind::BackupEligibilityChanged => (
                11,
                "backup eligibility differs from the stored credential's; reject the response",
            ),
            ErrorKind::Algorithm => (
                12,
                "credential algorithm was not offered or is not supported; offer it or reject the credential",
            ),
            ErrorKind::UnknownFormat => (
                13,
                "attestation format is not supported; reject the credential or request attestation none",
            ),
            ErrorKind::FormatDisabled => (
                14,
                "attestation format's feature is off; enable the feature or reject the credential",
            ),
            ErrorKind::AttestationInvalid => {
                (15, "attestation does not verify; reject the credential")
            }
            ErrorKind::Untrusted => (
                16,
                "attestation is not trusted; reject the credential or change the trust policy",
            ),
            ErrorKind::CredentialIdInvalid => (
                17,
                "credential id is too long or differs from the raw id; reject the credential",
            ),
            ErrorKind::NotAllowed => (
                18,
                "credential is not in the allow list; reject the response",
            ),
            ErrorKind::CredentialMismatch => (
                19,
                "credential id is not the stored credential's; look up the stored credential by the response's id",
            ),
            ErrorKind::UserHandleMismatch => (
                20,
                "user handle is missing or names another user; reject the response",
            ),
            ErrorKind::BrowserMismatch => (
                21,
                "browser binding differs from the one the ceremony started with; reject the response and restart the ceremony",
            ),
            ErrorKind::Signature => (22, "signature does not verify; reject the response"),
            ErrorKind::CounterRegressed => (
                23,
                "signature counter did not advance; treat the credential as possibly cloned or change the counter policy",
            ),
            ErrorKind::Extension => (
                24,
                "extension was not requested or contradicts the request; reject the response",
            ),
            ErrorKind::Expired => (25, "ceremony has expired; restart the ceremony"),
            ErrorKind::Corrupt => (
                26,
                "stored record does not decode; discard the record and restart the ceremony",
            ),
        }
    }

    const ALL: [ErrorKind; 27] = [
        ErrorKind::Malformed,
        ErrorKind::TooLarge,
        ErrorKind::Type,
        ErrorKind::ChallengeMismatch,
        ErrorKind::OriginMismatch,
        ErrorKind::CrossOriginDenied,
        ErrorKind::TopOriginDenied,
        ErrorKind::RpIdHash,
        ErrorKind::UserNotPresent,
        ErrorKind::UserNotVerified,
        ErrorKind::BackupStateWithoutEligibility,
        ErrorKind::BackupEligibilityChanged,
        ErrorKind::Algorithm,
        ErrorKind::UnknownFormat,
        ErrorKind::FormatDisabled,
        ErrorKind::AttestationInvalid,
        ErrorKind::Untrusted,
        ErrorKind::CredentialIdInvalid,
        ErrorKind::NotAllowed,
        ErrorKind::CredentialMismatch,
        ErrorKind::UserHandleMismatch,
        ErrorKind::BrowserMismatch,
        ErrorKind::Signature,
        ErrorKind::CounterRegressed,
        ErrorKind::Extension,
        ErrorKind::Expired,
        ErrorKind::Corrupt,
    ];

    #[test]
    fn each_kind_reads_distinctly() {
        for (at, kind) in ALL.into_iter().enumerate() {
            let (index, text) = row(kind);
            assert_eq!(index, at, "{kind:?} is out of order in ALL");
            assert_eq!(format!("{}", Error::new(kind)), text);
            // fixed prose: no quoting, bracketing or digits that could carry input or a Debug form
            assert!(
                text.chars()
                    .all(|c| c.is_ascii_alphabetic() || " ;,'_-".contains(c)),
                "{kind:?}: {text}"
            );
            assert!(!text.contains(&format!("{kind:?}")));
        }
        let texts: BTreeSet<_> = ALL.iter().map(|&k| format!("{}", Error::new(k))).collect();
        assert_eq!(texts.len(), ALL.len());
    }

    #[test]
    fn display_names_kind_and_step() {
        let text = row(ErrorKind::Type).1;
        let at = |step| Error {
            kind: ErrorKind::Type,
            step,
        };
        assert_eq!(format!("{}", Error::new(ErrorKind::Type)), text);
        assert_eq!(
            format!("{}", at(Some(SpecStep::Registration(9)))),
            format!("{text} at registration step 9")
        );
        assert_eq!(
            format!("{}", at(Some(SpecStep::Authentication(10)))),
            format!("{text} at authentication step 10")
        );
        assert_eq!(
            at(Some(SpecStep::Authentication(3))).spec_step(),
            Some(SpecStep::Authentication(3))
        );
        assert_eq!(Error::new(ErrorKind::Type).spec_step(), None);
        assert_eq!(
            Error::at(ErrorKind::Type, SpecStep::Registration(2)),
            at(Some(SpecStep::Registration(2)))
        );
    }
}
