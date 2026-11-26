//! Attestation results and trust: formats, types, anchors and the `TrustSource` a registration asks (R49, R50, R57); anchors with webauthn-09.
use core::marker::PhantomData;

/// An attestation statement format (L3 section 8); each has its own cargo feature.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Format {
    /// `none` (8.7).
    None,
    /// `packed` (8.2).
    Packed,
    /// `tpm` (8.3).
    Tpm,
    /// `android-key` (8.4).
    AndroidKey,
    /// `apple` (8.8).
    Apple,
    /// `fido-u2f` (8.6).
    FidoU2f,
}

/// The attestation type a format's verification yields (L3 6.5.3).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttestationType {
    /// No attestation.
    None,
    /// Signed by the credential key itself.
    SelfAttestation,
    /// Basic attestation.
    Basic,
    /// Attestation CA.
    AttCa,
    /// Anonymization CA.
    AnonCa,
    /// Basic or AttCA, which the format cannot tell apart.
    Uncertain,
}

/// Whether the trust path ended at an anchor from the `TrustSource`.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trust {
    /// The chain, or its leaf, matched an anchor.
    Anchored,
    /// None, self, an internally valid chain that met no anchor, or a chain signed by an algorithm the walk does not verify (C7).
    Unanchored,
}

/// How a registration was attested; enough to sweep stored credentials after a CA compromise (L3 13.4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attestation(());

/// Where registrations find acceptable attestation roots and refusals (L3 7.1 step 23). Implemented by hosts and by `webauthn-mds`.
pub trait TrustSource {
    /// Decide one statement with a trust path; never asked for none or self attestation.
    fn decide(&self, query: &TrustQuery<'_>) -> TrustDecision<'_>;
}

/// A `TrustSource`'s answer for one statement.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub enum TrustDecision<'a> {
    /// The anchors acceptable for this format and model.
    Anchors(&'a [TrustAnchor]),
    /// The model or a certificate in the chain is revoked or refused: `Untrusted` under every `TrustPolicy`.
    Denied,
    /// Nothing known: the statement is `Unanchored`.
    Unknown,
}

/// What a `TrustSource` is asked.
#[derive(Clone, Copy, Debug)]
pub struct TrustQuery<'a>(PhantomData<&'a ()>);

/// A root certificate, parsed and bounded; its X.509 form stays inside the crate.
#[derive(Clone, Debug)]
pub struct TrustAnchor(());
