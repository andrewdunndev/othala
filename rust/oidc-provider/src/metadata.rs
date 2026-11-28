use serde::Serialize;

use crate::error::{Error, ErrorKind};
use crate::issuer::IssuerUrl;

pub(crate) const AUTHORIZE: &str = "/authorize";
pub(crate) const TOKEN: &str = "/token";
pub(crate) const JWKS: &str = "/jwks.json";
/// OpenID Connect Discovery 1.0 section 4: the issuer, then this.
pub(crate) const DISCOVERY: &str = "/.well-known/openid-configuration";

/// The provider's one discovery document (OpenID Connect Discovery 1.0 section 3). Each member either has no default
/// or is written out because its default claims more than this provider does.
#[derive(Serialize)]
struct Metadata<'a> {
    issuer: &'a str,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    response_types_supported: [&'static str; 1],
    response_modes_supported: [&'static str; 1],
    grant_types_supported: [&'static str; 1],
    subject_types_supported: [&'static str; 1],
    id_token_signing_alg_values_supported: [&'static str; 1],
    token_endpoint_auth_methods_supported: [&'static str; 2],
    code_challenge_methods_supported: [&'static str; 1],
    scopes_supported: [&'static str; 1],
    claims_supported: [&'static str; 7],
    request_parameter_supported: bool,
    request_uri_parameter_supported: bool,
    claims_parameter_supported: bool,
    authorization_response_iss_parameter_supported: bool,
}

/// The document's bytes for `issuer`.
pub(crate) fn document(issuer: &IssuerUrl) -> Result<Vec<u8>, Error> {
    let at = |suffix: &str| format!("{}{suffix}", issuer.as_str());
    serde_json::to_vec(&Metadata {
        issuer: issuer.as_str(),
        authorization_endpoint: at(AUTHORIZE),
        token_endpoint: at(TOKEN),
        jwks_uri: at(JWKS),
        response_types_supported: ["code"],
        response_modes_supported: ["query"],
        grant_types_supported: ["authorization_code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        token_endpoint_auth_methods_supported: ["client_secret_basic", "none"],
        code_challenge_methods_supported: ["S256"],
        scopes_supported: ["openid"],
        claims_supported: ["iss", "sub", "aud", "exp", "iat", "auth_time", "nonce"],
        request_parameter_supported: false,
        request_uri_parameter_supported: false,
        claims_parameter_supported: false,
        authorization_response_iss_parameter_supported: true,
    })
    .map_err(|_| Error::new(ErrorKind::Malformed))
}
