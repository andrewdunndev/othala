use core::fmt;

use jose::{AnyVerifyKey, Jwk, JwkEntry, JwkSet, SigningAlg};
use serde::Deserialize;

use crate::error::{Error, ErrorKind};

/// The most keys one provider publishes.
pub const MAX_KEYS: usize = 8;

/// The public keys the provider publishes and signs under: one or more RS256 keys (OpenID Connect Core 1.0 section
/// 15.1), each with its own `kid`, which is what lets a key be rotated in before it signs. Public keys only, by the
/// type of `jose::Jwk`.
pub struct SigningKeys {
    set: JwkSet,
}

#[derive(Deserialize)]
struct Members {
    #[serde(rename = "use")]
    usage: Option<String>,
}

impl SigningKeys {
    /// The keys, in the order they are published. None is `Missing` and more than `MAX_KEYS` is `TooLarge`. Each key
    /// needs a `kid` (`Missing`), `alg` `RS256`, `use` `sig`, and to be an RSA key of at least 2048 bits (all
    /// `Malformed`); a `kid` given twice is `Duplicate`.
    pub fn new(keys: Vec<Jwk>) -> Result<Self, Error> {
        if keys.is_empty() {
            return Err(Error::new(ErrorKind::Missing));
        }
        if keys.len() > MAX_KEYS {
            return Err(Error::new(ErrorKind::TooLarge));
        }
        keys.iter().try_for_each(check)?;
        Ok(Self {
            set: JwkSet::new(keys)?,
        })
    }

    /// The `kid` of each key, in publication order.
    pub fn kids(&self) -> impl Iterator<Item = &str> {
        self.set.entries().filter_map(|entry| match entry {
            JwkEntry::Public(key) => key.kid().map(jose::Kid::as_str),
            _ => None,
        })
    }

    pub(crate) const fn set(&self) -> &JwkSet {
        &self.set
    }
}

fn check(key: &Jwk) -> Result<(), Error> {
    if key.kid().is_none() {
        return Err(Error::new(ErrorKind::Missing));
    }
    AnyVerifyKey::from_jwk_for(key, SigningAlg::Rs256)?;
    let members = serde_json::to_vec(key)
        .and_then(|json| serde_json::from_slice::<Members>(&json))
        .map_err(|_| Error::new(ErrorKind::Malformed))?;
    if key.sig_alg() != Some(SigningAlg::Rs256) || members.usage.as_deref() != Some("sig") {
        return Err(Error::new(ErrorKind::Malformed));
    }
    Ok(())
}

impl fmt::Debug for SigningKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKeys")
            .field("kids", &self.kids().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}
