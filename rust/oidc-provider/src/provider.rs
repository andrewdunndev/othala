use core::fmt;

use http::header::CONTENT_TYPE;
use http::{HeaderValue, Method, Request, Response, StatusCode};
use jose::JwkSet;

use crate::error::{Error, ErrorKind};
use crate::issuer::IssuerUrl;
use crate::keys::SigningKeys;
use crate::lifetimes::Lifetimes;
use crate::metadata::{self, AUTHORIZE, DISCOVERY, JWKS, TOKEN};

/// The longest request body the provider looks at.
pub const MAX_BODY: usize = 16_384;
/// The longest request target, path and query, the provider looks at.
pub const MAX_TARGET: usize = 8_192;

/// Where a request goes. Decided from the method and path alone, so a host routes before it reads a body.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// `GET` or `POST` of the authorization endpoint (OpenID Connect Core 3.1.2.1).
    Authorize,
    /// `POST` of the token endpoint (RFC 6749 3.2).
    Token,
    /// `GET` of the discovery document.
    Metadata,
    /// `GET` of the JWKS.
    Jwks,
    /// Any other path, or any other method on a known path.
    NotFound,
    /// The target is longer than `MAX_TARGET`.
    TargetTooLong,
    /// The body is longer than `MAX_BODY`.
    BodyTooLarge,
}

/// One OpenID provider: its issuer, lifetimes and keys, and the discovery document and JWKS they determine. It holds
/// no clock, store or secret.
pub struct Provider {
    issuer: IssuerUrl,
    lifetimes: Lifetimes,
    keys: SigningKeys,
    metadata: Vec<u8>,
    jwks: Vec<u8>,
}

impl Provider {
    /// The provider for `issuer`, with its discovery document and JWKS built once.
    pub fn new(issuer: IssuerUrl, lifetimes: Lifetimes, keys: SigningKeys) -> Result<Self, Error> {
        Ok(Self {
            metadata: metadata::document(&issuer)?,
            jwks: serde_json::to_vec(keys.set()).map_err(|_| Error::new(ErrorKind::Malformed))?,
            issuer,
            lifetimes,
            keys,
        })
    }

    /// The issuer.
    pub const fn issuer(&self) -> &IssuerUrl {
        &self.issuer
    }

    /// The lifetimes.
    pub const fn lifetimes(&self) -> Lifetimes {
        self.lifetimes
    }

    /// The published keys.
    pub const fn jwks(&self) -> &JwkSet {
        self.keys.set()
    }

    /// The discovery document, as served.
    pub fn metadata_json(&self) -> &[u8] {
        &self.metadata
    }

    /// Routes `request`: an oversize target or body first, then the method and path against the endpoints the
    /// discovery document advertises.
    pub fn route(&self, request: &Request<Vec<u8>>) -> Route {
        let target = request
            .uri()
            .path_and_query()
            .map_or(0, |t| t.as_str().len());
        if target > MAX_TARGET {
            return Route::TargetTooLong;
        }
        if request.body().len() > MAX_BODY {
            return Route::BodyTooLarge;
        }
        let Some(rest) = request.uri().path().strip_prefix(self.issuer.path()) else {
            return Route::NotFound;
        };
        match (request.method(), rest) {
            (&Method::GET | &Method::POST, AUTHORIZE) => Route::Authorize,
            (&Method::POST, TOKEN) => Route::Token,
            (&Method::GET, DISCOVERY) => Route::Metadata,
            (&Method::GET, JWKS) => Route::Jwks,
            _ => Route::NotFound,
        }
    }

    /// The answer to a route this crate serves: the discovery document and the JWKS as `application/json`, and
    /// 404, 414 and 413 with no body. `Authorize` and `Token` are answered by the endpoints that later items add, so
    /// they give `None`.
    pub fn respond(&self, route: Route) -> Option<Response<Vec<u8>>> {
        match route {
            Route::Metadata => Some(json(self.metadata.clone())),
            Route::Jwks => Some(json(self.jwks.clone())),
            Route::NotFound => Some(status(StatusCode::NOT_FOUND)),
            Route::TargetTooLong => Some(status(StatusCode::URI_TOO_LONG)),
            Route::BodyTooLarge => Some(status(StatusCode::PAYLOAD_TOO_LARGE)),
            _ => None,
        }
    }
}

fn json(body: Vec<u8>) -> Response<Vec<u8>> {
    let mut response = Response::new(body);
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn status(code: StatusCode) -> Response<Vec<u8>> {
    let mut response = Response::new(Vec::new());
    *response.status_mut() = code;
    response
}

impl fmt::Debug for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Provider")
            .field("issuer", &self.issuer.as_str())
            .field("keys", &self.keys)
            .field("lifetimes", &self.lifetimes)
            .finish_non_exhaustive()
    }
}
