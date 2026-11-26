// `just canary` appends this to each published crate's src/lib.rs; each `want:` line's allow is rejected (E0453).
/// canary
#[allow(clippy::unwrap_used)] // want: E0453
pub fn canary_allow() {}
/// canary
#[expect(clippy::disallowed_methods, reason = "canary")] // want: E0453
pub fn canary_expect_lint() {}
/// canary
#[allow(clippy::restriction)] // want: E0453
pub fn canary_group() {}
/// canary
#[allow(clippy::option_unwrap_used)] // want: E0453
pub fn canary_renamed() {}
