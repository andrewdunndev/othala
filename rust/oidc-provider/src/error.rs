use core::fmt;

use http::header::{CACHE_CONTROL, CONTENT_TYPE, PRAGMA};
use http::{HeaderValue, Response, StatusCode};

/// Why a value was refused; never carries input.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// The value is outside its grammar or range.
    Malformed,
    /// A required value was not given.
    Missing,
    /// Two values name the same `kid`.
    Duplicate,
    /// The value is longer, or the list longer, than its bound.
    TooLarge,
}

/// The crate's one construction error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    kind: ErrorKind,
}

impl Error {
    pub(crate) const fn new(kind: ErrorKind) -> Self {
        Self { kind }
    }

    /// Why the value was refused.
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl From<jose::Error> for Error {
    fn from(e: jose::Error) -> Self {
        Self::new(match e.kind() {
            jose::ErrorKind::TooLarge => ErrorKind::TooLarge,
            jose::ErrorKind::DuplicateMember => ErrorKind::Duplicate,
            _ => ErrorKind::Malformed,
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.kind {
            ErrorKind::Malformed => "value outside its grammar or range",
            ErrorKind::Missing => "a required value was not given",
            ErrorKind::Duplicate => "a kid is named twice",
            ErrorKind::TooLarge => "value or list exceeds its bound",
        })
    }
}

impl core::error::Error for Error {}

/// The registered error codes of RFC 6749 4.1.2.1 and 5.2 and OpenID Connect Core 3.1.2.6 this provider can answer with.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    /// `invalid_request`
    InvalidRequest,
    /// `invalid_client`
    InvalidClient,
    /// `invalid_grant`
    InvalidGrant,
    /// `unauthorized_client`
    UnauthorizedClient,
    /// `unsupported_grant_type`
    UnsupportedGrantType,
    /// `unsupported_response_type`
    UnsupportedResponseType,
    /// `invalid_scope`
    InvalidScope,
    /// `access_denied`
    AccessDenied,
    /// `login_required`
    LoginRequired,
    /// `consent_required`
    ConsentRequired,
    /// `request_not_supported`
    RequestNotSupported,
    /// `request_uri_not_supported`
    RequestUriNotSupported,
    /// `registration_not_supported`
    RegistrationNotSupported,
    /// `server_error`
    ServerError,
}

impl ErrorCode {
    /// The registered code string.
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::AccessDenied => "access_denied",
            Self::LoginRequired => "login_required",
            Self::ConsentRequired => "consent_required",
            Self::RequestNotSupported => "request_not_supported",
            Self::RequestUriNotSupported => "request_uri_not_supported",
            Self::RegistrationNotSupported => "registration_not_supported",
            Self::ServerError => "server_error",
        }
    }

    /// The HTTP status of a direct (non-redirect) answer: 401 for `invalid_client` and 500 for `server_error`
    /// (RFC 6749 5.2, RFC 9110 15.6.1), else 400.
    pub const fn status(self) -> StatusCode {
        match self {
            Self::InvalidClient => StatusCode::UNAUTHORIZED,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        }
    }

    /// The JSON body `{"error":"<name>"}`, with no `error_description`.
    pub fn body(self) -> Vec<u8> {
        let mut body = br#"{"error":""#.to_vec();
        body.extend_from_slice(self.name().as_bytes());
        body.extend_from_slice(b"\"}");
        body
    }

    /// The direct answer: [`Self::status`], [`Self::body`] as `application/json`, and `Cache-Control: no-store` with
    /// `Pragma: no-cache` (RFC 6749 5.1, 5.2). A `WWW-Authenticate` challenge on 401 is the token endpoint's to add.
    pub fn response(self) -> Response<Vec<u8>> {
        let mut response = Response::new(self.body());
        *response.status_mut() = self.status();
        let headers = response.headers_mut();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
        response
    }
}
