/// Whatever decodes re-encodes to the same text, and every byte string survives a round trip.
pub(crate) fn check(data: &[u8]) {
    if let Ok(text) = core::str::from_utf8(data)
        && let Ok(bytes) = base::b64url_decode(text)
    {
        assert_eq!(base::b64url_encode(&bytes), text);
    }
    assert_eq!(
        base::b64url_decode(&base::b64url_encode(data))
            .ok()
            .as_deref(),
        Some(data)
    );
}
