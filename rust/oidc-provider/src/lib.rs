//! An OpenID Connect provider's issuer, discovery document, JWKS, routing and error responses, as pure functions over
//! `http` values. The authorization and token endpoints are advertised and routed here and answered by later items.

mod error;
mod issuer;
mod keys;
mod lifetimes;
mod metadata;
mod provider;

pub use error::{Error, ErrorCode, ErrorKind};
pub use issuer::{IssuerUrl, MAX_ISSUER};
pub use keys::{MAX_KEYS, SigningKeys};
pub use lifetimes::{Lifetimes, LifetimesBuilder, MAX_CODE_SECS, MAX_TICKET_SECS, MAX_TOKEN_SECS};
pub use provider::{MAX_BODY, MAX_TARGET, Provider, Route};
