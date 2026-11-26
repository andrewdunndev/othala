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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.kind)?;
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
    use alloc::format;

    use super::{Error, ErrorKind, SpecStep};

    #[test]
    fn display_names_kind_and_step() {
        let at = |step| Error {
            kind: ErrorKind::Type,
            step,
        };
        assert_eq!(format!("{}", Error::new(ErrorKind::Type)), "Type");
        assert_eq!(
            format!("{}", at(Some(SpecStep::Registration(9)))),
            "Type at registration step 9"
        );
        assert_eq!(
            format!("{}", at(Some(SpecStep::Authentication(10)))),
            "Type at authentication step 10"
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
