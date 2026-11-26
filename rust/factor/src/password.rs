#![expect(
    dead_code,
    reason = "fields are read by the bodies factor-05 and factor-07 land"
)]

use alloc::string::{String, ToString};
use core::fmt;

use argon2::password_hash::{self, PasswordHasher};
use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use base::{Entropy, SecretBytes};

use crate::{Error, ErrorKind};

const MAX_PASSWORD: usize = 4_096;
const MAX_MEMORY_KIB: u32 = 65_536;
const MAX_PASSES_AND_LANES: u32 = 64;
const SALT_LEN: usize = 16;
const TAG_LEN: usize = 32;

const fn within(n: u32) -> bool {
    n >= 1 && n <= MAX_PASSES_AND_LANES
}

const fn err(kind: ErrorKind) -> Error {
    Error { kind }
}

/// The one path to `argon2`: version 19, Argon2id, the given tag length, and optional secret and associated data.
pub(crate) fn argon2id<'k>(
    memory: Memory,
    passes: Passes,
    lanes: Lanes,
    tag: usize,
    secret: &'k [u8],
    ad: &[u8],
) -> Result<Argon2<'k>, Error> {
    let range = |_| err(ErrorKind::OutOfRange);
    let params = ParamsBuilder::new()
        .m_cost(memory.0)
        .t_cost(passes.0)
        .p_cost(lanes.0)
        .output_len(tag)
        .data(AssociatedData::new(ad).map_err(range)?)
        .build()
        .map_err(range)?;
    Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params).map_err(range)
}

/// A password as presented at login: 1 byte to 4,096 bytes of UTF-8, wiped on drop by base.
pub struct Password(SecretBytes);

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Password").finish_non_exhaustive()
    }
}

/// Which NIST SP 800-63B-4 minimum a new password meets.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Minimum {
    /// 15 code points: the password alone authenticates.
    SingleFactor,
    /// 8 code points: the password is only ever one factor of several.
    MultiFactor,
}

/// A password a subject chose, held to its length rule; only these are hashed.
pub struct NewPassword(Password);

impl NewPassword {
    /// Accepts up to 4,096 bytes and at least 15 (`SingleFactor`) or 8 (`MultiFactor`) Unicode scalar values.
    pub fn new(text: &str, minimum: Minimum) -> Result<Self, Error> {
        if text.len() > MAX_PASSWORD {
            return Err(err(ErrorKind::TooLarge));
        }
        let least = match minimum {
            Minimum::SingleFactor => 15,
            Minimum::MultiFactor => 8,
        };
        if text.chars().count() < least {
            return Err(err(ErrorKind::PasswordLength));
        }
        Ok(Self(Password(SecretBytes::new(text.as_bytes().to_vec()))))
    }
}

impl fmt::Debug for NewPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewPassword").finish_non_exhaustive()
    }
}

/// Argon2id memory in KiB.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Memory(u32);

/// Argon2id passes over memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Passes(u32);

/// Argon2id lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Lanes(u32);

/// An Argon2id cost at or above an OWASP minimum configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cost {
    memory: Memory,
    passes: Passes,
    lanes: Lanes,
}

impl Memory {
    /// `kib` kibibytes; `Cost::new` bounds it.
    pub const fn kib(kib: u32) -> Self {
        Self(kib)
    }
}

impl Passes {
    /// `passes` passes; `Cost::new` bounds it.
    pub const fn new(passes: u32) -> Self {
        Self(passes)
    }
}

impl Lanes {
    /// `lanes` lanes; `Cost::new` bounds it.
    pub const fn new(lanes: u32) -> Self {
        Self(lanes)
    }
}

impl Cost {
    /// Accepts 1 to 64 passes and lanes and up to 65,536 KiB, and only at or above an OWASP Password Storage Argon2id point.
    pub const fn new(memory: Memory, passes: Passes, lanes: Lanes) -> Result<Self, Error> {
        if !within(passes.0) || !within(lanes.0) || memory.0 > MAX_MEMORY_KIB {
            return Err(err(ErrorKind::OutOfRange));
        }
        let (m, t) = (memory.0, passes.0);
        if (m >= 47_104 && t >= 1)
            || (m >= 19_456 && t >= 2)
            || (m >= 12_288 && t >= 3)
            || (m >= 9_216 && t >= 4)
            || (m >= 7_168 && t >= 5)
        {
            return Ok(Self {
                memory,
                passes,
                lanes,
            });
        }
        Err(err(ErrorKind::WeakCost))
    }
}

/// An Argon2id v19 hash in canonical PHC string form, held to this crate's policy; the host stores it.
#[derive(Clone)]
pub struct Phc(String);

impl Phc {
    /// The canonical PHC text, for the host to store.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Phc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Phc").finish_non_exhaustive()
    }
}

/// Argon2id v19 at `cost`, with a 16-byte salt from `e` and a 32-byte tag.
pub fn password_hash(
    password: &NewPassword,
    cost: Cost,
    e: &mut impl Entropy,
) -> Result<Phc, Error> {
    let mut salt = [0; SALT_LEN];
    e.fill(&mut salt);
    let argon = argon2id(cost.memory, cost.passes, cost.lanes, TAG_LEN, &[], &[])?;
    let hash = argon
        .hash_password_with_salt(password.0.0.expose(), &salt)
        .map_err(|e| match e {
            password_hash::Error::OutOfMemory => err(ErrorKind::OutOfMemory),
            _ => err(ErrorKind::Internal),
        })?;
    Ok(Phc(hash.to_string()))
}

/// Whether a matched hash is below the cost the verifier was given.
#[non_exhaustive]
#[derive(Clone)]
pub enum Rehash {
    /// The stored hash meets the cost.
    Current,
    /// The presented password hashed again at the cost, for the host to store in place of the old hash.
    Needed(Phc),
}

/// A presented password matched the stored hash.
pub struct PasswordMatch {
    rehash: Rehash,
}

#[cfg(test)]
mod rfc9106 {
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    use serde::Deserialize;
    use testkit::vectors::{Outcome, run};

    use super::{Lanes, Memory, Passes, argon2id};
    use crate::tests::unhex;

    #[derive(Deserialize)]
    struct Case {
        password: String,
        salt: String,
        secret: String,
        ad: String,
        t: u32,
        m: u32,
        p: u32,
        taglen: usize,
        expect: Out,
    }

    #[derive(Deserialize)]
    struct Out {
        out: String,
    }

    fn tag(c: &Case) -> Option<Vec<u8>> {
        let secret = unhex(&c.secret)?;
        let ctx = argon2id(
            Memory::kib(c.m),
            Passes::new(c.t),
            Lanes::new(c.p),
            c.taglen,
            &secret,
            &unhex(&c.ad)?,
        )
        .ok()?;
        let mut out = vec![0; c.taglen];
        ctx.hash_password_into(&unhex(&c.password)?, &unhex(&c.salt)?, &mut out)
            .ok()?;
        Some(out)
    }

    #[test]
    fn section_5_3() {
        run(testkit::vector!("rfc9106/argon2id.json"), 1, |c: &Case| {
            assert_eq!(tag(c), unhex(&c.expect.out));
            Outcome::Checked
        });
    }
}
