//! The browser an oracle case names by 32 bytes.
use base::{BrowserBinding, Secret};

/// Equal bytes are one browser and any other bytes another: the bytes stand for the secret the browser's cookie holds.
pub(crate) fn browser(bytes: &[u8]) -> Result<BrowserBinding, &'static str> {
    let secret = <[u8; 32]>::try_from(bytes).map_err(|_| "browser")?;
    Ok(BrowserBinding::from(&Secret::new(secret)))
}
