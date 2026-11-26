#![allow(dead_code)]
use webauthn_rp::ErrorKind::{
    Algorithm, AttestationInvalid, BackupEligibilityChanged, BackupStateWithoutEligibility,
    BrowserMismatch, ChallengeMismatch, Corrupt, CounterRegressed, CredentialIdInvalid,
    CredentialMismatch, CrossOriginDenied, Expired, Extension, FormatDisabled, Malformed,
    NotAllowed, OriginMismatch, RpIdHash, Signature, TooLarge, TopOriginDenied, Type, UnknownFormat,
    Untrusted, UserHandleMismatch, UserNotPresent, UserNotVerified,
};
fn code(k: webauthn_rp::ErrorKind) -> u8 {
    match k {
        Malformed | TooLarge | Type | ChallengeMismatch | OriginMismatch | CrossOriginDenied
        | TopOriginDenied | RpIdHash | UserNotPresent | UserNotVerified | BackupStateWithoutEligibility
        | BackupEligibilityChanged | Algorithm | UnknownFormat | FormatDisabled | AttestationInvalid
        | Untrusted | CredentialIdInvalid | NotAllowed | CredentialMismatch | UserHandleMismatch
        | BrowserMismatch | Signature | CounterRegressed | Extension | Expired | _ => 0,
    }
}
fn main() {}
