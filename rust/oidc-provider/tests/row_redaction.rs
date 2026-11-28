//! Debug shows the issuer, the kids and the lifetimes, and no key member (CONTRACT R13).
mod common;

use common::{Result, modulus, provider};

#[test]
fn provider_debug_is_exactly_this() -> Result {
    let p = provider("https://op.example", &["k1", "k2"])?;
    let want = r#"Provider { issuer: "https://op.example", keys: SigningKeys { kids: ["k1", "k2"], .. }, lifetimes: Lifetimes { code: 60, access_token: 3600, id_token: 600, ticket: 300 }, .. }"#;
    assert_eq!(format!("{p:?}"), want);
    assert!(!format!("{p:#?}").contains(&modulus()?));
    Ok(())
}
