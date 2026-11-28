//! Unbuilt: The own attestation chain walk over x509-cert (R110 to R117); lands with webauthn-09.
use base::Digest;

/// How a chain walk that did not fail ended (R117).
#[expect(dead_code, reason = "built and read by the chain walk, webauthn-09")]
pub(crate) enum Walk {
    /// The chain met the anchor with this digest.
    Anchored(Digest),
    /// Internally valid but met no anchor, or signed by an algorithm the walk does not verify.
    Unanchored,
}
