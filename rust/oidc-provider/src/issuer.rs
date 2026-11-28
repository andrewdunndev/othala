use crate::error::{Error, ErrorKind};

/// The longest issuer URL in bytes.
pub const MAX_ISSUER: usize = 256;

const SCHEME: &str = "https://";

/// An issuer identifier (OpenID Connect Core 1.0 section 2, Discovery 1.0 section 3): an `https` URL with a host,
/// an optional port and an optional path, and no query, fragment, userinfo, percent-encoding or trailing slash. The
/// text is kept as given, since relying parties compare it byte for byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerUrl {
    text: String,
    issuer: jose::Issuer,
    path_start: usize,
}

impl IssuerUrl {
    /// Parses `text`: past `MAX_ISSUER` bytes is `TooLarge`; anything outside the form above is `Malformed`. The host
    /// is lowercase letters, digits and hyphens in dot-separated labels (no IP literal), and a path segment is
    /// letters, digits and `-._~`, never `.` or `..`.
    pub fn parse(text: &str) -> Result<Self, Error> {
        if text.len() > MAX_ISSUER {
            return Err(Error::new(ErrorKind::TooLarge));
        }
        let malformed = || Error::new(ErrorKind::Malformed);
        let rest = text.strip_prefix(SCHEME).ok_or_else(malformed)?;
        let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        let path_ok = path
            .strip_prefix('/')
            .is_none_or(|p| p.split('/').all(segment));
        if !host.split('.').all(label) || !port.is_none_or(valid_port) || !path_ok {
            return Err(malformed());
        }
        Ok(Self {
            issuer: jose::Issuer::new(text)?,
            path_start: SCHEME.len() + authority.len(),
            text: text.to_owned(),
        })
    }

    /// The text as given.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The same value as jose's issuer, for the `iss` claim of a later ID token.
    pub const fn issuer(&self) -> &jose::Issuer {
        &self.issuer
    }

    /// The path, empty or starting with `/`, that every endpoint is relative to.
    pub(crate) fn path(&self) -> &str {
        self.text.get(self.path_start..).unwrap_or_default()
    }
}

fn label(label: &str) -> bool {
    !label.is_empty()
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_port(port: &str) -> bool {
    !port.starts_with('0')
        && port.bytes().all(|b| b.is_ascii_digit())
        && port.parse::<u16>().ok().is_some()
}

fn segment(segment: &str) -> bool {
    !matches!(segment, "" | "." | "..")
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}
