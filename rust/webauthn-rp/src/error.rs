//! The one error type: a kind plus the ceremony step that raised it (R145, R146).
//!
//! `Display` is for operators and logs, never for the client: a host shows the client one refusal for every ceremony
//! failure (O10).
use core::fmt;

/// The crate's one error type. `Display` says what failed, at which spec step, and what to do next, never input bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
    step: Option<SpecStep>,
}

/// Declares `ErrorKind` and, from the same lines, `ALL` and the fixed sentence of each kind, so a kind is written once.
/// A sentence is what failed, then the caller's next action; `Display` puts the step between them.
macro_rules! error_kinds {
    ($($(#[$meta:meta])* $name:ident => $what:literal, $action:literal,)*) => {
        /// Why a call failed. Kinds are for logs; a host shows the client one refusal for every ceremony failure (O10).
        #[non_exhaustive]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum ErrorKind {
            $($(#[$meta])* $name,)*
        }

        impl ErrorKind {
            /// Every kind, for the table test.
            #[cfg(test)]
            const ALL: &'static [Self] = &[$(Self::$name),*];

            /// What failed, with no input bytes.
            const fn what(self) -> &'static str {
                match self {
                    $(Self::$name => $what,)*
                }
            }

            /// The caller's next action.
            const fn action(self) -> &'static str {
                match self {
                    $(Self::$name => $action,)*
                }
            }
        }
    };
}

error_kinds! {
    /// Input is not well-formed, or is empty where a value is required: CBOR, JSON, COSE, DER, base64url or a field shape.
    Malformed => "input is not well-formed", "reject the request, it cannot be repaired",
    /// Input or a list exceeds its stated bound.
    TooLarge => "input exceeds a size bound", "reject the request",
    /// `C.type` is not the ceremony's type.
    Type => "client data type is not this ceremony's", "reject the response and restart the ceremony",
    /// `C.challenge` is not the ceremony's challenge.
    ChallengeMismatch => "challenge is not this ceremony's", "reject the response and restart the ceremony",
    /// `C.origin` is not an origin of the relying party.
    OriginMismatch => "origin is not one of the relying party's", "reject the response or add the origin to the relying party",
    /// `C.crossOrigin` is true and the relying party does not allow it.
    CrossOriginDenied => "cross-origin use is not allowed", "reject the response or allow it on the relying party",
    /// `C.topOrigin` is present and not allowed.
    TopOriginDenied => "top origin is not allowed", "reject the response or allow it on the relying party",
    /// `rpIdHash` is not the hash of the RP ID (or of the AppID, when used).
    RpIdHash => "RP ID hash does not match", "check that the relying party's id is the one the client used",
    /// The UP flag is not set where it must be.
    UserNotPresent => "user presence is not asserted", "reject the response and ask the user to retry",
    /// User verification is required and the UV flag is clear.
    UserNotVerified => "user verification is required but not asserted", "reject the response and ask the user to retry with verification",
    /// BS is set without BE.
    BackupStateWithoutEligibility => "backup state is set without backup eligibility", "reject the authenticator data as invalid",
    /// BE differs from the stored credential's.
    BackupEligibilityChanged => "backup eligibility differs from the stored credential's", "reject the response",
    /// The credential's algorithm was not offered, or is not supported.
    Algorithm => "credential algorithm was not offered or is not supported", "offer it or reject the credential",
    /// `fmt` names no supported attestation statement format.
    UnknownFormat => "attestation format is not supported", "reject the credential or request attestation none",
    /// `fmt` names a format whose cargo feature is off.
    FormatDisabled => "attestation format's feature is off", "enable the feature or reject the credential",
    /// The attestation statement or its certificate chain does not verify.
    AttestationInvalid => "attestation does not verify", "reject the credential",
    /// The attestation verified but is not trustworthy: denied by the `TrustSource`, or not anchored under `TrustPolicy::RequireTrusted`.
    Untrusted => "attestation is not trusted", "reject the credential or change the trust policy",
    /// The attested credential id is longer than `MAX_CREDENTIAL_ID` or differs from the response's raw id.
    CredentialIdInvalid => "credential id is too long or differs from the raw id", "reject the credential",
    /// The credential is not in the ceremony's allow list.
    NotAllowed => "credential is not in the allow list", "reject the response",
    /// The response's credential id is not the stored credential's.
    CredentialMismatch => "credential id is not the stored credential's", "look up the stored credential by the response's id",
    /// The user handle is missing where required, or names another user.
    UserHandleMismatch => "user handle is missing or names another user", "reject the response",
    /// The finishing browser's binding is not the one the ceremony started with.
    BrowserMismatch => "browser binding differs from the one the ceremony started with", "reject the response and restart the ceremony",
    /// The assertion signature does not verify.
    Signature => "signature does not verify", "reject the response",
    /// The signature counter did not advance under `CounterPolicy::Reject`.
    CounterRegressed => "signature counter did not advance", "treat the credential as possibly cloned or change the counter policy",
    /// An extension input or output was not requested, or contradicts the request.
    Extension => "extension was not requested or contradicts the request", "reject the response",
    /// The ceremony is at or past its deadline.
    Expired => "ceremony has expired", "restart the ceremony",
    /// A stored record does not decode, or a row is not the record kind its key names.
    Corrupt => "stored record does not decode", "discard the record and restart the ceremony",
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind.what())?;
        match self.step {
            Some(SpecStep::Registration(n)) => write!(f, " at registration step {n}")?,
            Some(SpecStep::Authentication(n)) => write!(f, " at authentication step {n}")?,
            None => {}
        }
        write!(f, "; {}", self.kind.action())
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;
    use alloc::format;

    use super::{Error, ErrorKind, SpecStep};

    /// The exact text of every kind without a step. The match has no `_` arm, so a new kind fails to compile here;
    /// `ErrorKind::ALL` comes from the same macro lines as the enum, so no kind can be left out of the loop below.
    fn expected(kind: ErrorKind) -> &'static str {
        match kind {
            ErrorKind::Malformed => {
                "input is not well-formed; reject the request, it cannot be repaired"
            }
            ErrorKind::TooLarge => "input exceeds a size bound; reject the request",
            ErrorKind::Type => {
                "client data type is not this ceremony's; reject the response and restart the ceremony"
            }
            ErrorKind::ChallengeMismatch => {
                "challenge is not this ceremony's; reject the response and restart the ceremony"
            }
            ErrorKind::OriginMismatch => {
                "origin is not one of the relying party's; reject the response or add the origin to the relying party"
            }
            ErrorKind::CrossOriginDenied => {
                "cross-origin use is not allowed; reject the response or allow it on the relying party"
            }
            ErrorKind::TopOriginDenied => {
                "top origin is not allowed; reject the response or allow it on the relying party"
            }
            ErrorKind::RpIdHash => {
                "RP ID hash does not match; check that the relying party's id is the one the client used"
            }
            ErrorKind::UserNotPresent => {
                "user presence is not asserted; reject the response and ask the user to retry"
            }
            ErrorKind::UserNotVerified => {
                "user verification is required but not asserted; reject the response and ask the user to retry with verification"
            }
            ErrorKind::BackupStateWithoutEligibility => {
                "backup state is set without backup eligibility; reject the authenticator data as invalid"
            }
            ErrorKind::BackupEligibilityChanged => {
                "backup eligibility differs from the stored credential's; reject the response"
            }
            ErrorKind::Algorithm => {
                "credential algorithm was not offered or is not supported; offer it or reject the credential"
            }
            ErrorKind::UnknownFormat => {
                "attestation format is not supported; reject the credential or request attestation none"
            }
            ErrorKind::FormatDisabled => {
                "attestation format's feature is off; enable the feature or reject the credential"
            }
            ErrorKind::AttestationInvalid => "attestation does not verify; reject the credential",
            ErrorKind::Untrusted => {
                "attestation is not trusted; reject the credential or change the trust policy"
            }
            ErrorKind::CredentialIdInvalid => {
                "credential id is too long or differs from the raw id; reject the credential"
            }
            ErrorKind::NotAllowed => "credential is not in the allow list; reject the response",
            ErrorKind::CredentialMismatch => {
                "credential id is not the stored credential's; look up the stored credential by the response's id"
            }
            ErrorKind::UserHandleMismatch => {
                "user handle is missing or names another user; reject the response"
            }
            ErrorKind::BrowserMismatch => {
                "browser binding differs from the one the ceremony started with; reject the response and restart the ceremony"
            }
            ErrorKind::Signature => "signature does not verify; reject the response",
            ErrorKind::CounterRegressed => {
                "signature counter did not advance; treat the credential as possibly cloned or change the counter policy"
            }
            ErrorKind::Extension => {
                "extension was not requested or contradicts the request; reject the response"
            }
            ErrorKind::Expired => "ceremony has expired; restart the ceremony",
            ErrorKind::Corrupt => {
                "stored record does not decode; discard the record and restart the ceremony"
            }
        }
    }

    #[test]
    fn each_kind_reads_distinctly() {
        for &kind in ErrorKind::ALL {
            let text = expected(kind);
            assert_eq!(format!("{}", Error::new(kind)), text);
            // fixed prose: no quoting, bracketing or digits that could carry input or a Debug form
            assert!(
                text.chars()
                    .all(|c| c.is_ascii_alphabetic() || " ;,'_-".contains(c)),
                "{kind:?}: {text}"
            );
            assert!(!text.contains(&format!("{kind:?}")));
        }
        let texts: BTreeSet<_> = ErrorKind::ALL
            .iter()
            .map(|&k| format!("{}", Error::new(k)))
            .collect();
        assert_eq!(texts.len(), ErrorKind::ALL.len());
    }

    #[test]
    fn display_names_kind_and_step() {
        let at = |step| Error {
            kind: ErrorKind::Type,
            step,
        };
        assert_eq!(
            format!("{}", Error::new(ErrorKind::Type)),
            "client data type is not this ceremony's; reject the response and restart the ceremony"
        );
        assert_eq!(
            format!("{}", at(Some(SpecStep::Registration(9)))),
            "client data type is not this ceremony's at registration step 9; reject the response and restart the ceremony"
        );
        assert_eq!(
            format!("{}", at(Some(SpecStep::Authentication(10)))),
            "client data type is not this ceremony's at authentication step 10; reject the response and restart the ceremony"
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
