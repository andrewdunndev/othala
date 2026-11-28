//! One body and one status per ErrorCode (CONTRACT R11).
use http::StatusCode;
use oidc_provider::ErrorCode::{self, *};

const ALL: [(ErrorCode, &str, u16); 14] = [
    (InvalidRequest, "invalid_request", 400),
    (InvalidClient, "invalid_client", 401),
    (InvalidGrant, "invalid_grant", 400),
    (UnauthorizedClient, "unauthorized_client", 400),
    (UnsupportedGrantType, "unsupported_grant_type", 400),
    (UnsupportedResponseType, "unsupported_response_type", 400),
    (InvalidScope, "invalid_scope", 400),
    (AccessDenied, "access_denied", 400),
    (LoginRequired, "login_required", 400),
    (ConsentRequired, "consent_required", 400),
    (RequestNotSupported, "request_not_supported", 400),
    (RequestUriNotSupported, "request_uri_not_supported", 400),
    (RegistrationNotSupported, "registration_not_supported", 400),
    (ServerError, "server_error", 500),
];

#[test]
fn each_code_has_its_name_status_and_body() {
    for (code, name, status) in ALL {
        assert_eq!(code.name(), name);
        assert_eq!(
            code.status(),
            StatusCode::from_u16(status).unwrap_or_default(),
            "{name}"
        );
        assert_eq!(code.body(), format!(r#"{{"error":"{name}"}}"#).into_bytes());
    }
}

#[test]
fn the_response_is_uncacheable_json() {
    for (code, name, status) in ALL {
        let r = code.response();
        assert_eq!(r.status().as_u16(), status);
        assert_eq!(r.body(), &format!(r#"{{"error":"{name}"}}"#).into_bytes());
        let header = |h: &str| r.headers().get(h).map(|v| v.as_bytes().to_vec());
        assert_eq!(header("content-type"), Some(b"application/json".to_vec()));
        assert_eq!(header("cache-control"), Some(b"no-store".to_vec()));
        assert_eq!(header("pragma"), Some(b"no-cache".to_vec()));
        assert_eq!(r.headers().len(), 3);
    }
}
