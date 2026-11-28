use crate::error::{Error, ErrorKind};

/// The longest authorization code lifetime, 10 minutes (RFC 6749 4.1.2: "A maximum authorization code lifetime of 10
/// minutes is RECOMMENDED").
pub const MAX_CODE_SECS: u64 = 600;
/// The longest access token and ID token lifetime, one day.
pub const MAX_TOKEN_SECS: u64 = 86_400;
/// The longest login or consent ticket lifetime, one hour.
pub const MAX_TICKET_SECS: u64 = 3_600;

/// How long each issued value lives, in seconds. Every one is set, nonzero and at most its bound; there is no default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lifetimes {
    code: u64,
    access_token: u64,
    id_token: u64,
    ticket: u64,
}

impl Lifetimes {
    /// A builder with nothing set.
    pub const fn builder() -> LifetimesBuilder {
        LifetimesBuilder {
            code: None,
            access_token: None,
            id_token: None,
            ticket: None,
        }
    }

    /// The authorization code lifetime.
    pub const fn code(&self) -> u64 {
        self.code
    }

    /// The access token lifetime.
    pub const fn access_token(&self) -> u64 {
        self.access_token
    }

    /// The ID token lifetime.
    pub const fn id_token(&self) -> u64 {
        self.id_token
    }

    /// The login and consent ticket lifetime.
    pub const fn ticket(&self) -> u64 {
        self.ticket
    }
}

/// Collects the four lifetimes; [`Self::build`] refuses one that is unset or out of range.
#[derive(Clone, Copy, Debug)]
pub struct LifetimesBuilder {
    code: Option<u64>,
    access_token: Option<u64>,
    id_token: Option<u64>,
    ticket: Option<u64>,
}

impl LifetimesBuilder {
    /// Sets the authorization code lifetime in seconds.
    #[must_use]
    pub const fn code(mut self, secs: u64) -> Self {
        self.code = Some(secs);
        self
    }

    /// Sets the access token lifetime in seconds.
    #[must_use]
    pub const fn access_token(mut self, secs: u64) -> Self {
        self.access_token = Some(secs);
        self
    }

    /// Sets the ID token lifetime in seconds.
    #[must_use]
    pub const fn id_token(mut self, secs: u64) -> Self {
        self.id_token = Some(secs);
        self
    }

    /// Sets the ticket lifetime in seconds.
    #[must_use]
    pub const fn ticket(mut self, secs: u64) -> Self {
        self.ticket = Some(secs);
        self
    }

    /// The lifetimes: an unset one is `Missing`, zero is `Malformed`, and one past its `MAX_*_SECS` is `TooLarge`.
    pub fn build(self) -> Result<Lifetimes, Error> {
        Ok(Lifetimes {
            code: bounded(self.code, MAX_CODE_SECS)?,
            access_token: bounded(self.access_token, MAX_TOKEN_SECS)?,
            id_token: bounded(self.id_token, MAX_TOKEN_SECS)?,
            ticket: bounded(self.ticket, MAX_TICKET_SECS)?,
        })
    }
}

fn bounded(secs: Option<u64>, max: u64) -> Result<u64, Error> {
    match secs {
        None => Err(Error::new(ErrorKind::Missing)),
        Some(0) => Err(Error::new(ErrorKind::Malformed)),
        Some(s) if s > max => Err(Error::new(ErrorKind::TooLarge)),
        Some(s) => Ok(s),
    }
}
