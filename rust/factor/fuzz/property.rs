/// Whatever decodes re-encodes to its input, and no input panics.
pub(crate) fn check(data: &[u8]) {
    if let Ok(record) = factor::Record::decode(data) {
        assert_eq!(record.encode(), data);
    }
}
