//! JWK decoding (RFC 7517, RFC 7518 section 6, RFC 8037 section 2) and the key-type-to-algorithm binding.
use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use base::{SecretBytes, b64url_decode};
use expose::Expose as _;
use rsa::BoxedUint;
use serde::de::IgnoredAny;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::alg::{CONTENT, SIGNING, registry_name};
use crate::json::{named, scan};
use crate::key::{Fam, Private, Public, dup, dup_private, private_info, public_info, public_of};
use crate::{
    Alg, DecryptKey, EncryptKey, Error, ErrorKind, JweAlg, KeyAlg, MAX_NAME_LEN, MAX_RSA_BITS,
    MAX_RSA_EXPONENT, MIN_RSA_BITS, PublicAlg, PublicKeyAlg, SignAlg, SigningAlg, SigningKey,
    VerifyKey,
};

/// A key id: an opaque lookup hint, compared byte for byte, never trusted.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Kid(pub(crate) String);

/// A JWK's key type (RFC 7518 section 6.1, RFC 8037 section 2).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kty {
    /// `EC`: P-256, P-384, or P-521 under `es512`.
    Ec,
    /// `RSA`.
    Rsa,
    /// `OKP`: Ed25519.
    Okp,
    /// `oct`: a symmetric key, only ever a [`SecretJwk`].
    Oct,
}

/// The members of a JWK beside its key material.
#[derive(Clone)]
pub(crate) struct Meta {
    pub(crate) kid: Option<Kid>,
    pub(crate) alg: Option<&'static str>,
    pub(crate) usage: Usage,
    /// `use` and `key_ops` as written, so a JWK serializes the members it was given.
    pub(crate) use_name: Option<&'static str>,
    pub(crate) ops: Vec<&'static str>,
}

/// The operations `use` and `key_ops` permit, one bit each; absent members permit every one the key type allows.
#[derive(Clone, Copy)]
pub(crate) struct Usage(pub(crate) u8);

pub(crate) const SIGN: u8 = 1;
pub(crate) const VERIFY: u8 = 2;
const WRAP: u8 = 4;
const UNWRAP: u8 = 8;
const DERIVE: u8 = 16;
const ENCRYPT: u8 = 32;
const DECRYPT: u8 = 64;
/// What `use: enc` permits.
const ENC_USE: u8 = WRAP + UNWRAP + DERIVE + ENCRYPT + DECRYPT;

/// A public JWK (RFC 7517, RFC 7518 section 6, RFC 8037 section 2): EC on P-256, P-384 or P-521, RSA, or OKP
/// Ed25519, never private or symmetric material. Opaque: members are read through accessors and written by
/// `Serialize`.
pub struct Jwk {
    pub(crate) meta: Meta,
    pub(crate) material: Public,
}

/// A JWK holding private or symmetric key material, opaque. Not `Clone`, not `Serialize`, `Debug` redacted.
pub struct SecretJwk {
    pub(crate) meta: Meta,
    pub(crate) material: Private,
}

/// A decoded key of either kind.
pub(crate) enum Key {
    Public(Public),
    Private(Private),
}

fn malformed() -> Error {
    ErrorKind::Malformed.into()
}

/// The public members read as `Cow` so an escaped value decodes (RFC 8259 7); the secret ones stay borrowed, so an
/// escaped one is refused and no unwiped copy of a secret is made.
#[derive(Deserialize)]
struct Raw<'a> {
    #[serde(borrow)]
    kty: Cow<'a, str>,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    key_ops: Option<Vec<String>>,
    #[serde(borrow)]
    crv: Option<Cow<'a, str>>,
    #[serde(borrow)]
    x: Option<Cow<'a, str>>,
    #[serde(borrow)]
    y: Option<Cow<'a, str>>,
    #[serde(borrow)]
    n: Option<Cow<'a, str>>,
    #[serde(borrow)]
    e: Option<Cow<'a, str>>,
    d: Option<&'a str>,
    p: Option<&'a str>,
    q: Option<&'a str>,
    dp: Option<&'a str>,
    dq: Option<&'a str>,
    qi: Option<&'a str>,
    #[serde(default, deserialize_with = "named")]
    oth: Option<Vec<IgnoredAny>>,
    k: Option<&'a str>,
}

fn bytes(text: Option<&str>) -> Result<SecretBytes, Error> {
    let text = text.ok_or_else(malformed)?;
    b64url_decode(text)
        .map(SecretBytes::new)
        .map_err(|_| malformed())
}

/// A member of exactly `len` octets.
fn field(text: Option<&str>, len: usize) -> Result<SecretBytes, Error> {
    let bytes = bytes(text)?;
    if bytes.expose().len() == len {
        Ok(bytes)
    } else {
        Err(malformed())
    }
}

/// A minimal Base64urlUInt (RFC 7518 section 2): not empty, no leading zero octet.
fn uint(text: Option<&str>) -> Result<SecretBytes, Error> {
    let bytes = bytes(text)?;
    match bytes.expose().first() {
        Some(0) | None => Err(malformed()),
        Some(_) => Ok(bytes),
    }
}

fn big(bytes: &SecretBytes) -> BoxedUint {
    BoxedUint::from_be_slice_vartime(bytes.expose())
}

macro_rules! curve {
    ($c:ident, $len:expr, $r:expr, $v:ident) => {{
        let (x, y) = (field($r.x.as_deref(), $len)?, field($r.y.as_deref(), $len)?);
        let point = [&[4][..], x.expose(), y.expose()].concat();
        let public = $c::PublicKey::from_sec1_bytes(&point).map_err(|_| malformed())?;
        match $r.d {
            None => Key::Public(Public::$v(public)),
            Some(d) => {
                let d = field(Some(d), $len)?;
                let secret = $c::SecretKey::from_slice(d.expose()).map_err(|_| malformed())?;
                if secret.public_key() != public {
                    return Err(malformed());
                }
                Key::Private(Private::$v(secret))
            }
        }
    }};
}

fn ec(r: &Raw<'_>) -> Result<Key, Error> {
    Ok(match r.crv.as_deref().ok_or_else(malformed)? {
        "P-256" => curve!(p256, 32, r, P256),
        "P-384" => curve!(p384, 48, r, P384),
        #[cfg(feature = "es512")]
        "P-521" => curve!(p521, 66, r, P521),
        _ => return Err(ErrorKind::UnsupportedAlg.into()),
    })
}

fn okp(r: &Raw<'_>) -> Result<Key, Error> {
    if r.crv.as_deref().ok_or_else(malformed)? != "Ed25519" {
        return Err(ErrorKind::UnsupportedAlg.into());
    }
    let array = |b: &SecretBytes| <[u8; 32]>::try_from(b.expose()).map_err(|_| malformed());
    let public = ed25519_dalek::VerifyingKey::from_bytes(&array(&field(r.x.as_deref(), 32)?)?)
        .map_err(|_| malformed())?;
    Ok(match r.d {
        None => Key::Public(Public::Ed25519(public)),
        Some(d) => {
            let secret = ed25519_dalek::SigningKey::from_bytes(&array(&field(Some(d), 32)?)?);
            if secret.verifying_key() != public {
                return Err(malformed());
            }
            Key::Private(Private::Ed25519(secret))
        }
    })
}

fn rsa(r: &Raw<'_>) -> Result<Key, Error> {
    let (n, e) = (uint(r.n.as_deref())?, uint(r.e.as_deref())?);
    // `uint` refuses a leading zero, so this byte bound is the bit bound and no big integer is built past it
    if n.expose().len() > MAX_RSA_BITS / 8 {
        return Err(ErrorKind::TooLarge.into());
    }
    let bits = usize::try_from(big(&n).bit_width_vartime()).unwrap_or(usize::MAX);
    if bits < MIN_RSA_BITS {
        return Err(ErrorKind::WeakKey.into());
    }
    let exponent = (e.expose().len() <= 8).then(|| {
        e.expose()
            .iter()
            .fold(0_u64, |sum, byte| sum * 256 + u64::from(*byte))
    });
    if exponent.is_none_or(|e| e > MAX_RSA_EXPONENT) {
        return Err(ErrorKind::TooLarge.into());
    }
    let private = [r.d, r.p, r.q, r.dp, r.dq, r.qi]
        .iter()
        .any(Option::is_some);
    if r.oth.is_some() {
        return Err(ErrorKind::UnsupportedAlg.into());
    }
    if !private {
        return rsa::PublicKey::new_with_size_limits(big(&n), big(&e), MIN_RSA_BITS..=MAX_RSA_BITS)
            .map(|key| Key::Public(Public::Rsa(key)))
            .map_err(|_| malformed());
    }
    let (d, p, q) = (uint(r.d)?, uint(r.p)?, uint(r.q)?);
    rsa::PrivateKey::from_components(big(&n), big(&e), big(&d), vec![big(&p), big(&q)])
        .map(|key| Key::Private(Private::Rsa(key)))
        .map_err(|_| malformed())
}

/// The `key_ops` values and the operations each permits.
const OPS: [(&str, u8); 8] = [
    ("sign", SIGN),
    ("verify", VERIFY),
    ("encrypt", ENCRYPT),
    ("wrapKey", WRAP),
    ("decrypt", DECRYPT),
    ("unwrapKey", UNWRAP),
    ("deriveKey", DERIVE),
    ("deriveBits", DERIVE),
];

fn usage(r: &Raw<'_>) -> Result<(Usage, Option<&'static str>, Vec<&'static str>), Error> {
    let (use_name, by_use) = match r.usage.as_deref() {
        None => (None, None),
        Some("sig") => (Some("sig"), Some(SIGN + VERIFY)),
        Some("enc") => (Some("enc"), Some(ENC_USE)),
        Some(_) => return Err(ErrorKind::KeyUse.into()),
    };
    let mut names = Vec::new();
    let mut ops = 0;
    for op in r.key_ops.iter().flatten() {
        let (name, bit) = OPS
            .iter()
            .find(|(name, _)| *name == op)
            .ok_or(ErrorKind::KeyUse)?;
        // RFC 7517 4.3: a value MUST NOT be repeated
        if names.contains(name) {
            return Err(ErrorKind::KeyUse.into());
        }
        names.push(*name);
        ops |= bit;
    }
    let bits = match (by_use, ops) {
        (None, 0) => u8::MAX,
        (Some(by_use), 0) => by_use,
        (None, ops) => ops,
        (Some(by_use), ops) if ops & !by_use == 0 => ops,
        (Some(_), _) => return Err(ErrorKind::KeyUse.into()),
    };
    Ok((Usage(bits), use_name, names))
}

fn meta(r: &Raw<'_>) -> Result<Meta, Error> {
    let alg = match r.alg.as_deref() {
        None => None,
        Some(a) => Some(registry_name(a).ok_or(ErrorKind::UnsupportedAlg)?),
    };
    let (usage, use_name, ops) = usage(r)?;
    Ok(Meta {
        kid: r.kid.as_deref().map(Kid::new).transpose()?,
        alg,
        usage,
        use_name,
        ops,
    })
}

/// The one JWK reader: a document is a public key, a private key or an `oct` key, and nothing else.
pub(crate) fn parse(json: &[u8]) -> Result<(Meta, Key), Error> {
    parse_filtered(json, false)?.ok_or_else(malformed)
}

/// As [`parse`]; with `public_only` a key carrying a private parameter or an `oct` key is `None`, before any is built.
pub(crate) fn parse_filtered(json: &[u8], public_only: bool) -> Result<Option<(Meta, Key)>, Error> {
    scan(json)?;
    let r: Raw<'_> = serde_json::from_slice(json).map_err(|_| malformed())?;
    let private = [r.d, r.p, r.q, r.dp, r.dq, r.qi]
        .iter()
        .any(Option::is_some);
    if public_only && (private || r.kty == "oct") {
        return Ok(None);
    }
    let key = match &*r.kty {
        "EC" => ec(&r)?,
        "RSA" => rsa(&r)?,
        "OKP" => okp(&r)?,
        "oct" => {
            let k = bytes(r.k)?;
            if k.expose().is_empty() {
                return Err(malformed());
            }
            Key::Private(Private::Oct(k))
        }
        _ => return Err(ErrorKind::UnsupportedAlg.into()),
    };
    Ok(Some((meta(&r)?, key)))
}

fn kty_of(fam: Fam) -> Kty {
    match fam {
        Fam::Oct => Kty::Oct,
        Fam::P256 | Fam::P384 | Fam::P521 => Kty::Ec,
        Fam::Ed25519 => Kty::Okp,
        Fam::Rsa => Kty::Rsa,
    }
}

/// The key family each algorithm takes (RFC 7518 section 3, RFC 8037 section 3.1), and the whole table.
const fn sig_fam(alg: SigningAlg) -> Fam {
    match alg {
        SigningAlg::Hs256 | SigningAlg::Hs384 | SigningAlg::Hs512 => Fam::Oct,
        SigningAlg::Rs256
        | SigningAlg::Rs384
        | SigningAlg::Rs512
        | SigningAlg::Ps256
        | SigningAlg::Ps384
        | SigningAlg::Ps512 => Fam::Rsa,
        SigningAlg::Es256 => Fam::P256,
        SigningAlg::Es384 => Fam::P384,
        SigningAlg::Es512 => Fam::P521,
        SigningAlg::EdDsa => Fam::Ed25519,
    }
}

/// The `key_ops` value a key serves `alg` under (RFC 7517 4.3): `dir` encrypts the content with the key, a key-wrapping
/// algorithm wraps the content key, and key agreement derives a key.
const fn jwe_op(alg: JweAlg, decrypt: bool) -> u8 {
    match (alg, decrypt) {
        (JweAlg::Dir, false) => ENCRYPT,
        (JweAlg::Dir, true) => DECRYPT,
        (
            JweAlg::EcdhEs | JweAlg::EcdhEsA128Kw | JweAlg::EcdhEsA192Kw | JweAlg::EcdhEsA256Kw,
            _,
        ) => DERIVE,
        (_, false) => WRAP,
        (_, true) => UNWRAP,
    }
}

const fn jwe_takes(alg: JweAlg, fam: Fam) -> bool {
    match alg {
        JweAlg::A128Kw
        | JweAlg::A192Kw
        | JweAlg::A256Kw
        | JweAlg::A128GcmKw
        | JweAlg::A192GcmKw
        | JweAlg::A256GcmKw
        | JweAlg::Dir => matches!(fam, Fam::Oct),
        JweAlg::EcdhEs | JweAlg::EcdhEsA128Kw | JweAlg::EcdhEsA192Kw | JweAlg::EcdhEsA256Kw => {
            matches!(fam, Fam::P256 | Fam::P384 | Fam::P521)
        }
        JweAlg::RsaOaep | JweAlg::RsaOaep256 => matches!(fam, Fam::Rsa),
    }
}

impl Meta {
    fn check(&self, takes: bool, name: &str, ops: u8) -> Result<(), Error> {
        if !takes || self.alg.is_some_and(|alg| alg != name) {
            Err(ErrorKind::AlgMismatch.into())
        } else if self.usage.0 & ops == 0 {
            Err(ErrorKind::KeyUse.into())
        } else {
            Ok(())
        }
    }

    /// `alg` is a JWS algorithm of the key's family, `ops` is permitted, and an HMAC key is as long as its hash.
    pub(crate) fn check_sig(
        &self,
        (fam, len): (Fam, usize),
        alg: SigningAlg,
        ops: u8,
    ) -> Result<(), Error> {
        self.check(fam == sig_fam(alg), alg.name(), ops)?;
        let floor = match alg {
            SigningAlg::Hs256 => 32,
            SigningAlg::Hs384 => 48,
            SigningAlg::Hs512 => 64,
            _ => 0,
        };
        if len < floor {
            return Err(ErrorKind::WeakKey.into());
        }
        Ok(())
    }

    /// `alg` is a JWE algorithm of the key's family, the operation `alg` needs on that key is permitted, and an AES key
    /// is as long as its algorithm says.
    pub(crate) fn check_jwe(
        &self,
        (fam, len): (Fam, usize),
        alg: JweAlg,
        decrypt: bool,
    ) -> Result<(), Error> {
        // a `dir` key names the content algorithm it serves as its `alg` (RFC 7516 A, RFC 7520 5.6)
        let enc = self
            .alg
            .filter(|a| alg == JweAlg::Dir && CONTENT.into_iter().any(|enc| enc.name() == *a));
        self.check(
            jwe_takes(alg, fam),
            enc.unwrap_or(alg.name()),
            jwe_op(alg, decrypt),
        )?;
        let want = match alg {
            JweAlg::A128Kw | JweAlg::A128GcmKw => 16,
            JweAlg::A192Kw | JweAlg::A192GcmKw => 24,
            JweAlg::A256Kw | JweAlg::A256GcmKw => 32,
            _ => len,
        };
        if len != want {
            return Err(ErrorKind::WeakKey.into());
        }
        Ok(())
    }

    pub(crate) fn sig_alg(&self) -> Option<SigningAlg> {
        SIGNING.into_iter().find(|alg| Some(alg.name()) == self.alg)
    }
}

impl Kid {
    /// A `kid`: not empty (`Malformed`), at most `MAX_NAME_LEN` bytes (`TooLarge`).
    pub fn new(text: &str) -> Result<Self, Error> {
        if text.is_empty() {
            Err(malformed())
        } else if text.len() > MAX_NAME_LEN {
            Err(ErrorKind::TooLarge.into())
        } else {
            Ok(Self(text.into()))
        }
    }

    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for Kid {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Kid {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

impl Jwk {
    /// Decodes a public JWK; private or symmetric members are `Malformed`.
    pub fn decode(json: &[u8]) -> Result<Self, Error> {
        match parse(json)? {
            (meta, Key::Public(material)) => Ok(Self { meta, material }),
            (_, Key::Private(_)) => Err(malformed()),
        }
    }

    /// The `kid`, when present.
    pub const fn kid(&self) -> Option<&Kid> {
        self.meta.kid.as_ref()
    }

    /// The key type.
    pub fn kty(&self) -> Kty {
        kty_of(public_info(&self.material).0)
    }

    /// The JWS algorithm the JWK's `alg` names, when it names one.
    pub fn sig_alg(&self) -> Option<SigningAlg> {
        self.meta.sig_alg()
    }

    /// A key that verifies `A`: the key's family takes `A`, its `alg` and usage allow it.
    pub fn verify_key<A: PublicAlg>(&self) -> Result<VerifyKey<A>, Error> {
        self.meta
            .check_sig(public_info(&self.material), A::ALG, VERIFY)?;
        Ok(VerifyKey {
            material: dup(&self.material),
            alg: PhantomData,
        })
    }

    /// A key that encrypts for `K`.
    pub fn encrypt_key<K: PublicKeyAlg>(&self) -> Result<EncryptKey<K>, Error> {
        self.meta
            .check_jwe(public_info(&self.material), K::ALG, false)?;
        Ok(EncryptKey {
            kid: self.meta.kid.clone(),
            material: dup(&self.material),
            alg: PhantomData,
        })
    }
}

impl Clone for Jwk {
    fn clone(&self) -> Self {
        Self {
            meta: self.meta.clone(),
            material: dup(&self.material),
        }
    }
}

impl fmt::Debug for Jwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Jwk")
            .field("kty", &self.kty())
            .field("kid", &self.meta.kid)
            .field("alg", &self.meta.alg)
            .finish()
    }
}

impl SecretJwk {
    /// Decodes a private or `oct` JWK; a public one is `Malformed`.
    pub fn decode(json: &[u8]) -> Result<Self, Error> {
        match parse(json)? {
            (meta, Key::Private(material)) => Ok(Self { meta, material }),
            (_, Key::Public(_)) => Err(malformed()),
        }
    }

    /// An `oct` key with no `kid`, `alg` or usage.
    pub const fn from_oct(key: SecretBytes) -> Self {
        Self {
            meta: Meta {
                kid: None,
                alg: None,
                usage: Usage(u8::MAX),
                use_name: None,
                ops: Vec::new(),
            },
            material: Private::Oct(key),
        }
    }

    /// The `kid`, when present.
    pub const fn kid(&self) -> Option<&Kid> {
        self.meta.kid.as_ref()
    }

    /// The key type.
    pub fn kty(&self) -> Kty {
        kty_of(private_info(&self.material).0)
    }

    /// The public half, keeping `kid`, `alg` and `use`; none for an `oct` key.
    pub fn public(&self) -> Option<Jwk> {
        let bits = match self.meta.use_name {
            Some("sig") => SIGN + VERIFY,
            Some(_) => ENC_USE,
            None => u8::MAX,
        };
        match self.material {
            Private::Oct(_) => None,
            _ => Some(Jwk {
                meta: Meta {
                    usage: Usage(bits),
                    ops: Vec::new(),
                    ..self.meta.clone()
                },
                material: public_of(&self.material),
            }),
        }
    }

    /// A key that verifies `A`.
    pub fn verify_key<A: Alg>(&self) -> Result<VerifyKey<A>, Error> {
        self.meta
            .check_sig(private_info(&self.material), A::ALG, VERIFY)?;
        Ok(VerifyKey {
            material: public_of(&self.material),
            alg: PhantomData,
        })
    }

    /// A key that signs `A`.
    pub fn signing_key<A: SignAlg>(&self) -> Result<SigningKey<A>, Error> {
        self.meta
            .check_sig(private_info(&self.material), A::ALG, SIGN)?;
        Ok(SigningKey {
            material: dup_private(&self.material),
            alg: PhantomData,
        })
    }

    /// A key that encrypts for `K`.
    pub fn encrypt_key<K: KeyAlg>(&self) -> Result<EncryptKey<K>, Error> {
        self.meta
            .check_jwe(private_info(&self.material), K::ALG, false)?;
        Ok(EncryptKey {
            kid: self.meta.kid.clone(),
            material: public_of(&self.material),
            alg: PhantomData,
        })
    }

    /// A key that decrypts for `K`.
    pub fn decrypt_key<K: KeyAlg>(&self) -> Result<DecryptKey<K>, Error> {
        self.meta
            .check_jwe(private_info(&self.material), K::ALG, true)?;
        Ok(DecryptKey {
            material: dup_private(&self.material),
            alg: PhantomData,
        })
    }
}

impl fmt::Debug for SecretJwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretJwk")
            .field("kty", &self.kty())
            .field("kid", &self.meta.kid)
            .field("alg", &self.meta.alg)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned as _;
    use alloc::collections::BTreeMap;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;
    use serde::Deserialize;
    use testkit::vector;
    use testkit::vectors::{Appendix, Example, Json, Outcome, figures, run, sections};

    use super::{DECRYPT, DERIVE, ENCRYPT, Key, SIGN, SIGNING, UNWRAP, VERIFY, WRAP, parse};
    use crate::alg::registry_names;
    use crate::key::{private_info, public_info};
    use crate::{ErrorKind, Jwk, Kid, Kty, MAX_NAME_LEN, SecretJwk};

    /// A JWK as members: a value that opens with `[` is written as JSON, any other as a string.
    type Members = BTreeMap<String, String>;

    fn text(key: &Members) -> String {
        let members: Vec<String> = key
            .iter()
            .map(|(name, value)| match value.starts_with('[') {
                true => format!("\"{name}\":{value}"),
                false => format!("\"{name}\":\"{value}\""),
            })
            .collect();
        format!("{{{}}}", members.join(","))
    }

    fn kind(key: &Members) -> Option<ErrorKind> {
        parse(text(key).as_bytes()).err().map(|e| e.kind())
    }

    fn figure(example: &str) -> Members {
        let mut found: Option<Example> = None;
        let tally = figures(vector!("rfc7520/jwk.json"), 1, |e, _| {
            if e.example == example {
                found = Some(e.clone());
            }
            Outcome::Checked
        });
        assert_eq!(tally.checked(), tally.total());
        let json = found
            .as_ref()
            .and_then(|e| e.figures.last())
            .and_then(|f| f.json.as_ref());
        json.map(Json::parse).unwrap_or_default()
    }

    fn with(key: &Members, name: &str, value: &str) -> Members {
        let mut key = key.clone();
        key.insert(name.to_owned(), value.to_owned());
        key
    }

    fn without(key: &Members, name: &str) -> Members {
        let mut key = key.clone();
        key.remove(name);
        key
    }

    fn oct() -> Members {
        without(&without(&figure("3.5"), "use"), "alg")
    }

    fn okp_private() -> Members {
        let mut file: Vec<Appendix> = Vec::new();
        let tally = sections(vector!("rfc8037/appendix-a.json"), 1, |a| {
            file.push(a.clone());
            Outcome::Checked
        });
        assert_eq!(tally.checked(), tally.total());
        let json = file
            .first()
            .and_then(|a| a.section.blocks.first())
            .and_then(|b| b.json.as_ref());
        json.map(Json::parse).unwrap_or_default()
    }

    fn ec_private() -> Members {
        #[derive(Deserialize)]
        struct Case {
            private_jwk: Option<Json>,
        }
        let mut found = Members::new();
        let tally = run::<Case>(vector!("rfc7518/appendix-c.json"), 1, |c| {
            if found.is_empty() {
                found = c.private_jwk.as_ref().map(Json::parse).unwrap_or_default();
            }
            Outcome::Checked
        });
        assert_eq!(tally.checked(), tally.total());
        found
    }

    #[derive(Deserialize)]
    struct Expect {
        ok: bool,
        kind: Option<String>,
    }

    #[derive(Deserialize)]
    struct Case {
        id: String,
        op: String,
        alg: Option<String>,
        jwk: Option<Json>,
        expect: Expect,
    }

    #[test]
    fn keys_bind_algorithms() {
        let tally = run::<Case>(vector!("jose-derived/keys.json"), 20, |case| {
            let Some((alg, jwk)) = SIGNING
                .into_iter()
                .find(|a| Some(a.name()) == case.alg.as_deref())
                .filter(|_| case.op == "jwk_verify_key")
                .zip(case.jwk.as_ref())
            else {
                return Outcome::NotApplicable;
            };
            let outcome = parse(jwk.text().as_bytes()).and_then(|(meta, key)| match key {
                Key::Public(k) => meta.check_sig(public_info(&k), alg, VERIFY),
                Key::Private(k) => meta.check_sig(private_info(&k), alg, VERIFY),
            });
            // `SecretJwk::decode` refuses a non-oct key before any binding, so the vector names `Malformed`;
            // this layer has no such step and binds the key type to the algorithm
            let kind = if case.id == "hs256-rsa-key" {
                Some("AlgMismatch")
            } else {
                case.expect.kind.as_deref()
            };
            testkit::vectors::assert_verdict(
                &outcome,
                case.expect.ok,
                kind,
                |e| e.kind(),
                jwk.text(),
            );
            if case.id == "eddsa-x25519-key" {
                assert_eq!(
                    parse(jwk.text().as_bytes()).err().map(|e| e.kind()),
                    Some(ErrorKind::UnsupportedAlg)
                );
            } else if case.id.ends_with("-key")
                && !case.expect.ok
                // with es512 off a P-521 key is refused whole, before any alg comparison
                && (cfg!(feature = "es512") || case.id != "es256-p521-key")
            {
                assert_eq!(
                    outcome.as_ref().err().map(|e| e.kind()),
                    Some(ErrorKind::AlgMismatch),
                    "{}",
                    case.id
                );
            }
            Outcome::Checked
        });
        assert_eq!((tally.total(), tally.checked()), (40, 26));
    }

    #[test]
    fn section3_keys() {
        for example in ["3.3", "3.4", "3.5", "3.6"] {
            assert!(kind(&figure(example)).is_none(), "{example}");
        }
        let (rsa, rsa_private) = (figure("3.3"), figure("3.4"));
        let (bad, large, weak) = (
            Some(ErrorKind::Malformed),
            Some(ErrorKind::TooLarge),
            Some(ErrorKind::WeakKey),
        );
        assert_eq!(kind(&without(&rsa, "e")), bad);
        for e in ["AAEAAQ", "AA", ""] {
            assert_eq!(kind(&with(&rsa, "e", e)), bad, "{e}");
        }
        assert_eq!(kind(&with(&rsa, "e", "AgAAAAA")), large);
        assert_eq!(kind(&with(&rsa, "e", "AQAAAAAAAAAA")), large);
        assert_eq!(kind(&with(&rsa, "e", "Af____8")), None);
        assert_eq!(kind(&with(&rsa, "n", "AQAB")), weak);
        let modulus = |bytes: usize| base::b64url_encode(&vec![0xff; bytes]);
        assert_eq!(kind(&with(&rsa, "n", &modulus(256))), None);
        assert_eq!(kind(&with(&rsa, "n", &modulus(1024))), None);
        assert_eq!(kind(&with(&rsa, "n", &modulus(1025))), large);
        assert_eq!(kind(&with(&rsa, "n", "AA")), bad);
        let leading = format!("A{}", rsa.get("n").map(String::as_str).unwrap_or_default());
        assert_eq!(kind(&with(&rsa, "n", &leading)), bad);
        for member in ["d", "p", "q"] {
            assert_eq!(kind(&without(&rsa_private, member)), bad, "{member}");
        }
        assert!(kind(&without(&without(&rsa_private, "dp"), "qi")).is_none());
        assert_eq!(kind(&with(&rsa_private, "d", "AQAB")), bad);
        assert_eq!(
            kind(&with(&rsa, "oth", "[]")),
            Some(ErrorKind::UnsupportedAlg)
        );
        assert_eq!(kind(&with(&rsa, "p", "AQAB")), bad);
        assert_eq!(kind(&without(&oct(), "k")), bad);
        assert_eq!(kind(&with(&oct(), "k", "")), bad);
        for kty in ["EC", "OKP", "RSA"] {
            assert_eq!(kind(&with(&oct(), "kty", kty)), bad, "{kty}");
        }
        assert_eq!(
            kind(&with(&oct(), "kty", "other")),
            Some(ErrorKind::UnsupportedAlg)
        );
    }

    #[test]
    fn private_keys_match_their_public() {
        let bad = Some(ErrorKind::Malformed);
        for key in [ec_private(), okp_private()] {
            assert!(kind(&key).is_none());
            assert!(kind(&without(&key, "d")).is_none());
            assert_eq!(kind(&with(&key, "d", "AQAB")), bad);
            let d = key.get("d").map(String::as_str).unwrap_or_default();
            let other = format!(
                "{}{}",
                if d.starts_with('A') { "B" } else { "A" },
                d.get(1..).unwrap_or_default()
            );
            assert_eq!(kind(&with(&key, "d", &other)), bad);
            assert_eq!(kind(&without(&key, "x")), bad);
            assert_eq!(kind(&without(&key, "crv")), bad);
        }
        let (ec, okp) = (ec_private(), okp_private());
        assert_eq!(kind(&with(&ec, "d", &"A".repeat(43))), bad);
        assert_eq!(kind(&without(&ec, "y")), bad);
        assert_eq!(
            kind(&with(&ec, "crv", "secp256k1")),
            Some(ErrorKind::UnsupportedAlg)
        );
        assert_eq!(
            kind(&with(&okp, "crv", "X25519")),
            Some(ErrorKind::UnsupportedAlg)
        );
        assert_eq!(kind(&with(&okp, "x", "AQAB")), bad);
        let secret = SecretJwk::decode(text(&ec).as_bytes()).ok();
        let public = Jwk::decode(text(&without(&ec, "d")).as_bytes()).ok();
        assert_eq!(secret.as_ref().map(SecretJwk::kty), Some(Kty::Ec));
        assert_eq!(public.as_ref().map(Jwk::kty), Some(Kty::Ec));
        assert!(secret.and_then(|s| s.public()).is_some());
    }

    #[test]
    fn the_public_half_keeps_use_and_drops_key_ops() {
        let public = |key: &Members| {
            let secret = SecretJwk::decode(text(key).as_bytes()).ok();
            secret
                .and_then(|s| s.public())
                .map(|p| (p.meta.usage.0, p.meta.ops.len(), p.meta.use_name))
        };
        let ec = ec_private();
        assert_eq!(public(&ec), Some((u8::MAX, 0, None)));
        assert_eq!(
            public(&with(&ec, "use", "sig")),
            Some((SIGN + VERIFY, 0, Some("sig")))
        );
        assert_eq!(
            public(&with(&ec, "use", "enc")),
            Some((WRAP | UNWRAP | DERIVE | ENCRYPT | DECRYPT, 0, Some("enc")))
        );
        assert_eq!(
            public(&with(&ec, "key_ops", "[\"sign\"]")),
            Some((u8::MAX, 0, None))
        );
    }

    #[cfg(feature = "es512")]
    #[test]
    fn p521_follows_the_feature() {
        for example in ["3.1", "3.2"] {
            assert!(kind(&figure(example)).is_none(), "{example}");
        }
        assert_eq!(
            kind(&with(&figure("3.2"), "d", "AQAB")),
            Some(ErrorKind::Malformed)
        );
    }

    #[test]
    fn usage_bits() {
        let usage = |key: &Members| parse(text(key).as_bytes()).map(|(m, _)| m.usage.0).ok();
        assert_eq!(usage(&oct()), Some(u8::MAX));
        assert_eq!(usage(&with(&oct(), "use", "sig")), Some(SIGN | VERIFY));
        assert_eq!(
            usage(&with(&oct(), "use", "enc")),
            Some(WRAP | UNWRAP | DERIVE | ENCRYPT | DECRYPT)
        );
        for (op, bits) in [
            ("sign", SIGN),
            ("verify", VERIFY),
            ("encrypt", ENCRYPT),
            ("wrapKey", WRAP),
            ("decrypt", DECRYPT),
            ("unwrapKey", UNWRAP),
            ("deriveKey", DERIVE),
            ("deriveBits", DERIVE),
        ] {
            let ops = format!("[\"{op}\"]");
            assert_eq!(usage(&with(&oct(), "key_ops", &ops)), Some(bits), "{op}");
        }
        assert_eq!(
            usage(&with(&oct(), "key_ops", "[\"sign\",\"verify\"]")),
            Some(SIGN | VERIFY)
        );
        assert_eq!(usage(&with(&oct(), "key_ops", "[]")), Some(u8::MAX));
        assert_eq!(
            kind(&with(&oct(), "key_ops", "[\"sign\",\"sign\"]")),
            Some(ErrorKind::KeyUse)
        );
        assert_eq!(
            usage(&with(&oct(), "key_ops", "[\"encrypt\",\"wrapKey\"]")),
            Some(ENCRYPT | WRAP)
        );
        let both = with(&with(&oct(), "use", "sig"), "key_ops", "[\"verify\"]");
        assert_eq!(usage(&both), Some(VERIFY));
        let clash = with(&with(&oct(), "use", "enc"), "key_ops", "[\"verify\"]");
        assert_eq!(kind(&clash), Some(ErrorKind::KeyUse));
        assert_eq!(kind(&with(&oct(), "use", "other")), Some(ErrorKind::KeyUse));
        assert_eq!(
            kind(&with(&oct(), "key_ops", "[\"other\"]")),
            Some(ErrorKind::KeyUse)
        );
        assert_eq!(
            kind(&with(&oct(), "alg", "none")),
            Some(ErrorKind::UnsupportedAlg)
        );
        assert_eq!(kind(&with(&oct(), "kid", "")), Some(ErrorKind::Malformed));
    }

    #[test]
    fn escaped_and_null_members() {
        // RFC 8259 7: an escape spells the same string, in the public members
        let escaped = text(&figure("3.3")).replacen("\"RSA\"", "\"R\\u0053A\"", 1);
        assert_eq!(
            Jwk::decode(escaped.as_bytes()).ok().map(|k| k.kty()),
            Some(Kty::Rsa)
        );
        // a secret member is read borrowed: an escaped one is refused, so no unwiped copy is made
        for (key, member) in [(oct(), "k"), (ec_private(), "d")] {
            let secret = text(&key).replacen(
                &format!("\"{member}\":\""),
                &format!("\"{member}\":\"\\u0041"),
                1,
            );
            assert_eq!(
                SecretJwk::decode(secret.as_bytes()).err().map(|e| e.kind()),
                Some(ErrorKind::Malformed),
                "{member}"
            );
        }
        let rsa = figure("3.3");
        let oth = |value: &str| {
            let json = text(&rsa).replacen('{', &format!("{{\"oth\":{value},"), 1);
            parse(json.as_bytes()).err().map(|e| e.kind())
        };
        assert_eq!(oth("null"), Some(ErrorKind::Malformed));
        assert_eq!(oth("5"), Some(ErrorKind::Malformed));
        assert_eq!(oth("[]"), Some(ErrorKind::UnsupportedAlg));
    }

    #[test]
    fn registry_names_decode() {
        let sig_alg = |key: &Members| {
            SecretJwk::decode(text(key).as_bytes())
                .ok()
                .map(|j| j.meta.sig_alg())
        };
        for name in registry_names() {
            let parsed = parse(text(&with(&oct(), "alg", name)).as_bytes());
            assert_eq!(parsed.map(|(m, _)| m.alg).ok(), Some(Some(name)));
        }
        for alg in SIGNING {
            assert_eq!(sig_alg(&with(&oct(), "alg", alg.name())), Some(Some(alg)));
        }
        assert_eq!(sig_alg(&oct()), Some(None));
        assert_eq!(sig_alg(&with(&oct(), "alg", "A128GCM")), Some(None));
    }

    #[test]
    fn algorithms_bind_keys() {
        use crate::{JweAlg, SigningAlg};
        let info = |key: &Members| match parse(text(key).as_bytes()) {
            Ok((m, Key::Private(k))) => Some((m, private_info(&k))),
            Ok((m, Key::Public(k))) => Some((m, public_info(&k))),
            Err(_) => None,
        };
        let kind = |r: Result<(), crate::Error>| r.err().map(|e| e.kind());
        let (mismatch, usage) = (Some(ErrorKind::AlgMismatch), Some(ErrorKind::KeyUse));
        let hs = info(&figure("3.5"));
        let hs = hs.as_ref();
        assert_eq!(
            hs.and_then(|(m, i)| kind(m.check_sig(*i, SigningAlg::Hs256, SIGN))),
            None
        );
        assert_eq!(
            hs.and_then(|(m, i)| kind(m.check_sig(*i, SigningAlg::Hs384, SIGN))),
            mismatch
        );
        assert_eq!(
            hs.and_then(|(m, i)| kind(m.check_sig(*i, SigningAlg::Es256, SIGN))),
            mismatch
        );
        assert_eq!(
            hs.and_then(|(m, i)| kind(m.check_sig(*i, SigningAlg::Hs256, WRAP))),
            usage
        );
        let sig_only = info(&without(&figure("3.5"), "alg"));
        let kw = info(&oct());
        let kw = kw.as_ref();
        assert_eq!(
            kw.and_then(|(m, i)| kind(m.check_jwe(*i, JweAlg::Dir, false))),
            None
        );
        assert_eq!(
            kw.and_then(|(m, i)| kind(m.check_jwe(*i, JweAlg::Dir, true))),
            None
        );
        assert_eq!(
            sig_only
                .as_ref()
                .and_then(|(m, i)| kind(m.check_jwe(*i, JweAlg::A128Kw, false))),
            usage
        );
        assert_eq!(
            kw.and_then(|(m, i)| kind(m.check_jwe(*i, JweAlg::EcdhEs, false))),
            mismatch
        );
        assert_eq!(
            kw.and_then(|(m, i)| kind(m.check_jwe(*i, JweAlg::RsaOaep, false))),
            mismatch
        );
        let aes = info(&figure("3.6"));
        let aes = aes.as_ref();
        assert_eq!(
            aes.and_then(|(m, i)| kind(m.check_jwe(*i, JweAlg::A128Kw, false))),
            mismatch
        );
        let rsa = info(&without(&figure("3.3"), "use"));
        let rsa = rsa.as_ref();
        assert_eq!(
            rsa.and_then(|(m, i)| kind(m.check_jwe(*i, JweAlg::RsaOaep256, false))),
            None
        );
        assert_eq!(
            rsa.and_then(|(m, i)| kind(m.check_jwe(*i, JweAlg::A128Kw, false))),
            mismatch
        );
        let ec = info(&without(&ec_private(), "d"));
        let ec = ec.as_ref();
        for alg in [
            JweAlg::EcdhEs,
            JweAlg::EcdhEsA128Kw,
            JweAlg::EcdhEsA192Kw,
            JweAlg::EcdhEsA256Kw,
        ] {
            assert_eq!(
                ec.and_then(|(m, i)| kind(m.check_jwe(*i, alg, false))),
                None
            );
        }
        assert_eq!(
            ec.and_then(|(m, i)| kind(m.check_jwe(*i, JweAlg::RsaOaep, false))),
            mismatch
        );
        let signed = with(&figure("3.3"), "alg", "RS256");
        assert_eq!(
            Jwk::decode(text(&signed).as_bytes())
                .ok()
                .and_then(|k| k.sig_alg()),
            Some(SigningAlg::Rs256)
        );
        assert_eq!(
            Jwk::decode(text(&figure("3.3")).as_bytes())
                .ok()
                .and_then(|k| k.sig_alg()),
            None
        );
    }

    #[test]
    fn key_ops_serve_one_operation_per_algorithm() {
        use crate::JweAlg;
        let ops = [
            "sign",
            "verify",
            "encrypt",
            "decrypt",
            "wrapKey",
            "unwrapKey",
            "deriveKey",
            "deriveBits",
        ];
        let ec = without(&ec_private(), "d");
        let rsa = without(&figure("3.3"), "use");
        let rows: [(&Members, JweAlg, [&[&str]; 2]); 6] = [
            (&oct(), JweAlg::Dir, [&["encrypt"], &["decrypt"]]),
            (&oct(), JweAlg::A256Kw, [&["wrapKey"], &["unwrapKey"]]),
            (&oct(), JweAlg::A256GcmKw, [&["wrapKey"], &["unwrapKey"]]),
            (&rsa, JweAlg::RsaOaep256, [&["wrapKey"], &["unwrapKey"]]),
            (&ec, JweAlg::EcdhEs, [&["deriveKey", "deriveBits"]; 2]),
            (&ec, JweAlg::EcdhEsA128Kw, [&["deriveKey", "deriveBits"]; 2]),
        ];
        for (key, alg, served) in rows {
            for (decrypt, served) in [false, true].into_iter().zip(served) {
                for op in ops {
                    let member = with(key, "key_ops", &format!("[\"{op}\"]"));
                    let got = match parse(text(&member).as_bytes()) {
                        Err(e) => Some(e.kind()),
                        Ok((m, k)) => {
                            let info = match &k {
                                Key::Private(k) => private_info(k),
                                Key::Public(k) => public_info(k),
                            };
                            m.check_jwe(info, alg, decrypt).err().map(|e| e.kind())
                        }
                    };
                    let want = (!served.contains(&op)).then_some(ErrorKind::KeyUse);
                    assert_eq!(got, want, "{alg:?} decrypt={decrypt} {op}");
                }
            }
        }
    }

    #[test]
    fn kid_bounds() {
        assert_eq!(
            Kid::new("").err().map(|e| e.kind()),
            Some(ErrorKind::Malformed)
        );
        let longest = "k".repeat(MAX_NAME_LEN);
        assert_eq!(
            Kid::new(&longest).map(|k| k.as_str().len()).ok(),
            Some(MAX_NAME_LEN)
        );
        let too_long = "k".repeat(MAX_NAME_LEN + 1);
        assert_eq!(
            Kid::new(&too_long).err().map(|e| e.kind()),
            Some(ErrorKind::TooLarge)
        );
        assert_eq!(
            serde_json::from_str::<Kid>("\"a\"").ok(),
            Kid::new("a").ok()
        );
        assert_eq!(
            serde_json::from_str::<Kid>("\"\"")
                .err()
                .map(|e| format!("{e}")),
            Some("input is not well-formed; reject it, it cannot be repaired".into())
        );
        let json = serde_json::to_string(&Kid::new("a").ok());
        assert_eq!(json.ok().as_deref(), Some("\"a\""));
    }

    #[test]
    fn debug_redacted() {
        let key = SecretJwk::decode(text(&figure("3.5")).as_bytes()).ok();
        let shown = format!("{key:?}");
        assert!(
            shown.contains("SecretJwk")
                && shown.contains("HS256")
                && !shown.contains("hJtXIZ2uSN5")
        );
        let public = Jwk::decode(text(&figure("3.3")).as_bytes()).ok();
        let shown = format!("{public:?}");
        assert!(
            shown.contains("Jwk") && shown.contains("bilbo.baggins") && !shown.contains("n4EPtAOC")
        );
    }
}
