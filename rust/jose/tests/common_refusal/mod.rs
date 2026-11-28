//! The kind each refusing JWE vector must be refused with. The vectors are pinned external files, so the kind is our
//! contract's, kept here by vector id; a refusing vector with no entry fails its row.
use jose::Error;

const REFUSALS: &[(&str, &str)] = &[
    ("a1-rsa-oaep-a256gcm-tampered-ciphertext", "Decrypt"),
    ("a1-rsa-oaep-a256gcm-tampered-encrypted-key", "Decrypt"),
    ("a1-rsa-oaep-a256gcm-tampered-iv", "Decrypt"),
    ("a1-rsa-oaep-a256gcm-tampered-tag", "Decrypt"),
    ("a1-rsa-oaep-a256gcm-truncated-tag", "Malformed"),
    ("a3-a128kw-a128cbc-hs256-tampered-ciphertext", "Decrypt"),
    ("a3-a128kw-a128cbc-hs256-tampered-encrypted-key", "Decrypt"),
    ("a3-a128kw-a128cbc-hs256-tampered-iv", "Decrypt"),
    ("a3-a128kw-a128cbc-hs256-tampered-tag", "Decrypt"),
    ("a3-a128kw-a128cbc-hs256-truncated-tag", "Malformed"),
    ("s5_2-compact-tampered-ciphertext", "Decrypt"),
    ("s5_2-compact-tampered-encrypted-key", "Decrypt"),
    ("s5_2-compact-tampered-iv", "Decrypt"),
    ("s5_2-compact-tampered-tag", "Decrypt"),
    ("s5_2-compact-truncated-tag", "Malformed"),
    ("s5_4-compact-tampered-ciphertext", "Decrypt"),
    ("s5_4-compact-tampered-encrypted-key", "Decrypt"),
    ("s5_4-compact-tampered-iv", "Decrypt"),
    ("s5_4-compact-tampered-tag", "Decrypt"),
    ("s5_4-compact-truncated-tag", "Malformed"),
    ("s5_5-compact-nonempty-encrypted-key", "Decrypt"),
    ("s5_5-compact-tampered-ciphertext", "Decrypt"),
    ("s5_5-compact-tampered-iv", "Decrypt"),
    ("s5_5-compact-tampered-tag", "Decrypt"),
    ("s5_5-compact-truncated-tag", "Malformed"),
    ("s5_6-compact-nonempty-encrypted-key", "Decrypt"),
    ("s5_6-compact-tampered-ciphertext", "Decrypt"),
    ("s5_6-compact-tampered-iv", "Decrypt"),
    ("s5_6-compact-tampered-tag", "Decrypt"),
    ("s5_6-compact-truncated-tag", "Malformed"),
    ("s5_7-compact-tampered-ciphertext", "Decrypt"),
    ("s5_7-compact-tampered-encrypted-key", "Decrypt"),
    ("s5_7-compact-tampered-iv", "Decrypt"),
    ("s5_7-compact-tampered-tag", "Decrypt"),
    ("s5_7-compact-truncated-tag", "Malformed"),
    ("s5_8-compact-tampered-ciphertext", "Decrypt"),
    ("s5_8-compact-tampered-encrypted-key", "Decrypt"),
    ("s5_8-compact-tampered-iv", "Decrypt"),
    ("s5_8-compact-tampered-tag", "Decrypt"),
    ("s5_8-compact-truncated-tag", "Malformed"),
    ("s5_9-compact-must-refuse", "UnsupportedAlg"),
    ("s5_9-flattened-must-refuse", "UnsupportedAlg"),
    ("s5_9-general-must-refuse", "UnsupportedAlg"),
    ("s5_13-general-recipient-1-must-refuse", "AlgMismatch"),
];

/// `outcome` is `Ok` exactly when `ok`; a refusal is the kind the vector names, else the one `REFUSALS` holds for `id`.
pub(crate) fn assert_outcome<T>(
    outcome: &Result<T, Error>,
    ok: bool,
    named: Option<&str>,
    id: &str,
) {
    let seen = outcome.as_ref().err().map(|e| format!("{:?}", e.kind()));
    if ok {
        assert_eq!(seen, None, "{id}");
        return;
    }
    let want = named.or_else(|| {
        REFUSALS
            .iter()
            .find(|(name, _)| *name == id)
            .map(|(_, kind)| *kind)
    });
    assert!(
        want.is_some(),
        "{id}: a refusing vector with no recorded kind"
    );
    assert_eq!(seen.as_deref(), want, "{id}");
}
