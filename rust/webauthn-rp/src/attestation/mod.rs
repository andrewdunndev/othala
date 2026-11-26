//! Attestation statement formats, each compiled only under its own feature (R100); dispatch and `none` (R90) with webauthn-05.
#[cfg(feature = "android-key")]
mod android_key;

#[cfg(feature = "apple")]
mod apple;

#[cfg(any(
    feature = "packed",
    feature = "tpm",
    feature = "android-key",
    feature = "apple",
    feature = "fido-u2f"
))]
mod chain;

#[cfg(feature = "fido-u2f")]
mod fido_u2f;

#[cfg(feature = "packed")]
mod packed;

#[cfg(feature = "tpm")]
mod tpm;
