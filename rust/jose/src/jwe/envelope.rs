//! JWE parsing, the recipient loop and issuing (RFC 7516), compact and JSON.
use alloc::borrow::ToOwned as _;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use base::{Entropy, SecretBytes, b64url_decode, b64url_encode};
use expose::Expose as _;
use serde::Deserialize;
use serde::de::IgnoredAny;
use serde_json::value::RawValue;

use crate::jwk::decode::{Capped, Key, named, parse, scan};
use crate::jwk::thumbprint::members;
use crate::jws::header::REGISTERED;
use crate::key::{Private, Public};
use crate::{
    Compact, Enc, Error, ErrorKind, KeyAlg, Kid, LocalKeyAlg, MAX_COMPACT_LEN, MAX_ENTRIES,
};

/// Per-algorithm operations, implemented beside each algorithm's markers.
#[expect(
    private_interfaces,
    reason = "sealed: these traits are unnameable outside the crate"
)]
pub(crate) mod sealed {
    use alloc::vec::Vec;

    use base::{Entropy, SecretBytes};

    use super::Params;
    use crate::key::{Private, Public};
    use crate::{Error, JweEnc};

    /// Makes one recipient's content-encryption key.
    pub trait KeyAlg {
        /// The CEK for `enc` and the JWE Encrypted Key (empty for direct use and agreement); any header parameter the
        /// algorithm adds (`epk`, `iv`, `tag`) goes in `params`, and all randomness comes from `e`.
        fn wrap(
            key: &Public,
            enc: JweEnc,
            params: &mut Params,
            e: &mut dyn Entropy,
        ) -> Result<(SecretBytes, Vec<u8>), Error>;
    }

    /// Recovers one recipient's content-encryption key without randomness.
    pub trait Unwrap: KeyAlg {
        /// The CEK for `enc`; any failure is `Decrypt`.
        fn unwrap(
            key: &Private,
            encrypted_key: &[u8],
            enc: JweEnc,
            params: &Params,
        ) -> Result<SecretBytes, Error>;
    }

    /// Recovers one recipient's content-encryption key through a blinded private-key operation, on one path: an
    /// OAEP failure yields a random CEK of the same length, so the content step fails as `Decrypt` (RFC 7516 11.5).
    #[cfg(feature = "rsa-decrypt")]
    pub trait BlindedUnwrap: KeyAlg {
        /// The CEK for `enc`, or a random one drawn from `e`.
        fn unwrap(
            key: &Private,
            encrypted_key: &[u8],
            enc: JweEnc,
            e: &mut dyn Entropy,
        ) -> SecretBytes;
    }

    /// Encrypts and decrypts content under a CEK.
    pub trait Enc {
        /// The CEK length in bytes.
        const CEK_LEN: usize;
        /// The IV length in bytes.
        const IV_LEN: usize;
        /// The ciphertext and authentication tag of `plaintext` under `cek`, `iv` and `aad`.
        fn seal(
            cek: &SecretBytes,
            iv: &[u8],
            aad: &[u8],
            plaintext: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>), Error>;
        /// The plaintext; any failure is `Decrypt`.
        fn open(
            cek: &SecretBytes,
            iv: &[u8],
            aad: &[u8],
            ciphertext: &[u8],
            tag: &[u8],
        ) -> Result<SecretBytes, Error>;
    }
}

/// One recipient's key-management header parameters.
pub(crate) struct Params {
    pub(crate) epk: Option<Arc<Public>>,
    pub(crate) apu: Vec<u8>,
    pub(crate) apv: Vec<u8>,
    pub(crate) iv: Option<[u8; 12]>,
    pub(crate) tag: Option<[u8; 16]>,
}

/// One recipient: the `alg` its headers name, its parameters and its encrypted key.
pub(crate) struct Recipient {
    pub(crate) alg: String,
    pub(crate) params: Params,
    pub(crate) encrypted_key: Vec<u8>,
}

/// A parsed JWE (RFC 7516), not decrypted: no accessor reaches its content, and `Debug` prints only the `kid`s.
pub struct Jwe<'a> {
    pub(crate) protected: &'a str,
    pub(crate) aad: Option<&'a str>,
    pub(crate) enc: String,
    pub(crate) iv: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) tag: Vec<u8>,
    pub(crate) recipients: Vec<Recipient>,
    pub(crate) kids: Vec<Kid>,
}

/// Decrypted JWE content and its authenticated `aad`. Not `Clone`, not `Serialize`, `Debug` redacted.
pub struct Plaintext {
    pub(crate) content: SecretBytes,
    pub(crate) aad: Option<Vec<u8>>,
}

/// A key that encrypts JWE content-encryption keys under `K`; it carries its JWK's `kid` into the header.
/// Not `Clone`, `Debug` redacted.
pub struct EncryptKey<K: KeyAlg> {
    pub(crate) kid: Option<Kid>,
    pub(crate) material: Public,
    pub(crate) alg: PhantomData<K>,
}

/// A key that decrypts JWEs under `K` and nothing else. Not `Clone`, not `Serialize`, `Debug` redacted.
pub struct DecryptKey<K: KeyAlg> {
    pub(crate) material: Private,
    pub(crate) alg: PhantomData<K>,
}

#[derive(Default, Deserialize)]
struct Fields<'a> {
    alg: Option<String>,
    enc: Option<String>,
    kid: Option<String>,
    #[serde(default, deserialize_with = "named")]
    zip: Option<String>,
    crit: Option<Vec<String>>,
    apu: Option<String>,
    apv: Option<String>,
    iv: Option<String>,
    tag: Option<String>,
    #[serde(borrow)]
    epk: Option<&'a RawValue>,
}

/// One header object read: its members, and every name it holds.
struct Header {
    fields: Fields<'static>,
    names: BTreeSet<String>,
    params: Params,
}

fn malformed() -> Error {
    ErrorKind::Malformed.into()
}

fn bytes(text: &str) -> Result<Vec<u8>, Error> {
    b64url_decode(text).map_err(|_| malformed())
}

fn fixed<const N: usize>(text: Option<&str>) -> Result<Option<[u8; N]>, Error> {
    text.map(|text| bytes(text)?.try_into().map_err(|_| malformed()))
        .transpose()
}

/// A header object: `zip` is refused (`null` or any non-string is `Malformed`, RFC 7516 4.1.3), and the `epk`, `iv`, `tag`, `apu` and `apv` are decoded.
fn read(json: &[u8]) -> Result<Header, Error> {
    scan(json)?;
    let fields: Fields<'_> = serde_json::from_slice(json).map_err(|_| malformed())?;
    let names: BTreeMap<String, IgnoredAny> =
        serde_json::from_slice(json).map_err(|_| malformed())?;
    if fields.zip.is_some() {
        return Err(ErrorKind::UnsupportedAlg.into());
    }
    let epk = match fields
        .epk
        .map(|raw| parse(raw.get().as_bytes()))
        .transpose()?
    {
        Some((_, Key::Public(key))) => Some(Arc::new(key)),
        Some(_) => return Err(malformed()),
        None => None,
    };
    let params = Params {
        epk,
        apu: fields
            .apu
            .as_deref()
            .map(bytes)
            .transpose()?
            .unwrap_or_default(),
        apv: fields
            .apv
            .as_deref()
            .map(bytes)
            .transpose()?
            .unwrap_or_default(),
        iv: fixed(fields.iv.as_deref())?,
        tag: fixed(fields.tag.as_deref())?,
    };
    let fields = Fields {
        alg: fields.alg,
        enc: fields.enc,
        kid: fields.kid,
        zip: None,
        crit: fields.crit,
        apu: None,
        apv: None,
        iv: None,
        tag: None,
        epk: None,
    };
    Ok(Header {
        fields,
        names: names.into_keys().collect(),
        params,
    })
}

/// The recipient the protected, shared unprotected and per-recipient headers make: a name in two of them is
/// `DuplicateMember`, `crit` belongs to the protected header only and is refused, and `enc` is required.
fn merge(
    protected: Option<&Header>,
    shared: Option<&Header>,
    own: Option<&Header>,
) -> Result<(String, Recipient, Option<Kid>), Error> {
    let blank = empty();
    let (protected, shared, own) = (
        protected.unwrap_or(&blank),
        shared.unwrap_or(&blank),
        own.unwrap_or(&blank),
    );
    let all = [protected, shared, own];
    let clash = all.iter().enumerate().any(|(i, a)| {
        all.iter()
            .skip(i + 1)
            .any(|b| a.names.intersection(&b.names).next().is_some())
    });
    if clash {
        return Err(ErrorKind::DuplicateMember.into());
    }
    if shared.fields.crit.is_some() || own.fields.crit.is_some() {
        return Err(malformed());
    }
    if let Some(crit) = &protected.fields.crit {
        let usable = !crit.is_empty()
            && crit
                .iter()
                .all(|name| !REGISTERED.contains(&name.as_str()) && protected.names.contains(name));
        return Err(if usable {
            ErrorKind::CriticalHeader
        } else {
            ErrorKind::Malformed
        }
        .into());
    }
    let enc = all
        .iter()
        .find_map(|header| header.fields.enc.clone())
        .ok_or_else(malformed)?;
    let mut alg = None;
    let mut kid = None;
    let mut params = Params {
        epk: None,
        apu: Vec::new(),
        apv: Vec::new(),
        iv: None,
        tag: None,
    };
    for header in all {
        alg = alg.or_else(|| header.fields.alg.clone());
        kid = kid.or_else(|| header.fields.kid.clone());
        let given = &header.params;
        params = Params {
            epk: params.epk.or_else(|| given.epk.clone()),
            apu: if given.apu.is_empty() {
                params.apu
            } else {
                given.apu.clone()
            },
            apv: if given.apv.is_empty() {
                params.apv
            } else {
                given.apv.clone()
            },
            iv: params.iv.or(given.iv),
            tag: params.tag.or(given.tag),
        };
    }
    let alg = alg.ok_or_else(malformed)?;
    let recipient = Recipient {
        alg,
        params,
        encrypted_key: Vec::new(),
    };
    Ok((enc, recipient, kid.and_then(|kid| Kid::new(&kid).ok())))
}

/// An `alg` that needs a feature that is off is `UnsupportedAlg` for a sole recipient; among several it is skipped as
/// not the key's `alg`.
fn supported(recipient: &Recipient) -> Result<(), Error> {
    #[cfg(not(feature = "rsa-decrypt"))]
    if matches!(recipient.alg.as_str(), "RSA-OAEP" | "RSA-OAEP-256") {
        return Err(ErrorKind::UnsupportedAlg.into());
    }
    let _ = recipient;
    Ok(())
}

fn empty() -> Header {
    Header {
        fields: Fields::default(),
        names: BTreeSet::new(),
        params: Params {
            epk: None,
            apu: Vec::new(),
            apv: Vec::new(),
            iv: None,
            tag: None,
        },
    }
}

#[derive(Deserialize)]
struct Entry<'a> {
    header: Option<&'a RawValue>,
    encrypted_key: Option<&'a str>,
}

#[derive(Deserialize)]
struct Document<'a> {
    protected: Option<&'a str>,
    unprotected: Option<&'a RawValue>,
    header: Option<&'a RawValue>,
    encrypted_key: Option<&'a str>,
    recipients: Option<Capped<Entry<'a>>>,
    aad: Option<&'a str>,
    iv: &'a str,
    ciphertext: &'a str,
    tag: &'a str,
}

impl<'a> Jwe<'a> {
    /// Parses a compact JWE: five canonical base64url segments, the first a JSON object header.
    pub fn parse(compact: &'a str) -> Result<Self, Error> {
        if compact.len() > MAX_COMPACT_LEN {
            return Err(ErrorKind::TooLarge.into());
        }
        let mut parts = compact.split('.');
        let (Some(protected), Some(key), Some(iv), Some(ciphertext), Some(tag), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(malformed());
        };
        let header = read(&bytes(protected)?)?;
        let (enc, mut recipient, kid) = merge(Some(&header), None, None)?;
        supported(&recipient)?;
        recipient.encrypted_key = bytes(key)?;
        Ok(Self {
            protected,
            aad: None,
            enc,
            iv: bytes(iv)?,
            ciphertext: bytes(ciphertext)?,
            tag: bytes(tag)?,
            recipients: vec![recipient],
            kids: kid.into_iter().collect(),
        })
    }

    /// Parses the general (`recipients`) or flattened JSON serialization; more than `MAX_ENTRIES` recipients is
    /// `TooLarge`.
    pub fn parse_json(json: &'a [u8]) -> Result<Self, Error> {
        scan(json)?;
        let document: Document<'a> = serde_json::from_slice(json).map_err(|_| malformed())?;
        let entries = match document.recipients {
            Some(entries) if document.header.is_none() && document.encrypted_key.is_none() => {
                entries.0
            }
            None => vec![Entry {
                header: document.header,
                encrypted_key: document.encrypted_key,
            }],
            Some(_) => return Err(malformed()),
        };
        if entries.len() > MAX_ENTRIES {
            return Err(ErrorKind::TooLarge.into());
        }
        if entries.is_empty() {
            return Err(malformed());
        }
        let protected = document.protected.unwrap_or_default();
        let first = if protected.is_empty() {
            None
        } else {
            Some(read(&bytes(protected)?)?)
        };
        let shared = document
            .unprotected
            .map(|raw| read(raw.get().as_bytes()))
            .transpose()?;
        let sole = entries.len() == 1;
        let mut enc: Option<String> = None;
        let mut recipients = Vec::new();
        let mut kids = Vec::new();
        for entry in entries {
            let own = entry
                .header
                .map(|raw| read(raw.get().as_bytes()))
                .transpose()?;
            let (found, mut recipient, kid) = merge(first.as_ref(), shared.as_ref(), own.as_ref())?;
            if enc.as_ref().is_some_and(|held| *held != found) {
                return Err(malformed());
            }
            if sole {
                supported(&recipient)?;
            }
            recipient.encrypted_key = entry
                .encrypted_key
                .map(bytes)
                .transpose()?
                .unwrap_or_default();
            enc = Some(found);
            kids.extend(kid);
            recipients.push(recipient);
        }
        Ok(Self {
            protected,
            aad: document.aad,
            enc: enc.ok_or_else(malformed)?,
            iv: bytes(document.iv)?,
            ciphertext: bytes(document.ciphertext)?,
            tag: bytes(document.tag)?,
            recipients,
            kids,
        })
    }

    /// The `kid`s the headers name, as hints only.
    pub fn kids(&self) -> &[Kid] {
        &self.kids
    }

    /// Decrypts through the first recipient whose `alg` is `K`'s and whose key opens it; the header `enc` must be
    /// `E`'s. `AlgMismatch` when no recipient has `K`'s `alg` or the `enc` differs, otherwise every failure is `Decrypt`.
    pub fn decrypt<K: LocalKeyAlg, E: Enc>(self, key: &DecryptKey<K>) -> Result<Plaintext, Error> {
        self.open::<E>(K::ALG.name(), |recipient| {
            <K as sealed::Unwrap>::unwrap(
                &key.material,
                &recipient.encrypted_key,
                E::ENC,
                &recipient.params,
            )
        })
    }

    /// As [`Self::decrypt`] for RSA-OAEP: the private-key operation is blinded from `e`, and an OAEP failure yields a
    /// random key of the right length, so the content step fails as `Decrypt` (RFC 7516 11.5).
    #[cfg(feature = "rsa-decrypt")]
    pub fn decrypt_blinded<K: crate::BlindedKeyAlg, E: Enc>(
        self,
        key: &DecryptKey<K>,
        e: &mut impl Entropy,
    ) -> Result<Plaintext, Error> {
        self.open::<E>(K::ALG.name(), |recipient| {
            Ok(<K as sealed::BlindedUnwrap>::unwrap(
                &key.material,
                &recipient.encrypted_key,
                E::ENC,
                &mut *e,
            ))
        })
    }

    fn open<E: Enc>(
        self,
        alg: &str,
        mut unwrap: impl FnMut(&Recipient) -> Result<SecretBytes, Error>,
    ) -> Result<Plaintext, Error> {
        if self.enc != E::ENC.name() {
            return Err(ErrorKind::AlgMismatch.into());
        }
        let aad = match self.aad {
            Some(extra) => format!("{}.{extra}", self.protected),
            None => self.protected.to_owned(),
        };
        let mut named = false;
        for recipient in &self.recipients {
            if recipient.alg != alg {
                continue;
            }
            named = true;
            let opened = unwrap(recipient).and_then(|cek| {
                <E as sealed::Enc>::open(
                    &cek,
                    &self.iv,
                    aad.as_bytes(),
                    &self.ciphertext,
                    &self.tag,
                )
            });
            if let Ok(content) = opened {
                let aad = self
                    .aad
                    .map(bytes)
                    .transpose()
                    .map_err(|_| Error::from(ErrorKind::Decrypt))?;
                return Ok(Plaintext { content, aad });
            }
        }
        Err(if named {
            ErrorKind::Decrypt
        } else {
            ErrorKind::AlgMismatch
        }
        .into())
    }
}

impl Plaintext {
    /// The decrypted content.
    pub fn bytes(&self) -> &[u8] {
        self.content.expose()
    }

    /// The additional authenticated data of a JSON serialization, when it had one.
    pub fn aad(&self) -> Option<&[u8]> {
        self.aad.as_deref()
    }
}

impl<K: KeyAlg> EncryptKey<K> {
    /// Encrypts `plaintext` as a compact JWE under `K` and `E`; the CEK, IV and any ephemeral key come only from `e`.
    pub fn encrypt<E: Enc>(
        &self,
        plaintext: &[u8],
        e: &mut impl Entropy,
    ) -> Result<Compact, Error> {
        self.seal::<E>(plaintext, e, false)
    }

    //= https://www.rfc-editor.org/rfc/rfc7519#section-7.1
    //# * Else, if the JWT is a JWE, create a JWE using the Message as the plaintext for the JWE;
    //# all steps specified in [JWE] for creating a JWE MUST be followed.
    /// Encrypts a compact JWS as a nested JWT: the header gets `cty` `JWT` (RFC 7519 5.2).
    pub fn encrypt_jwt<E: Enc>(
        &self,
        jwt: &Compact,
        e: &mut impl Entropy,
    ) -> Result<Compact, Error> {
        self.seal::<E>(jwt.as_str().as_bytes(), e, true)
    }

    fn seal<E: Enc>(
        &self,
        plaintext: &[u8],
        e: &mut impl Entropy,
        nested: bool,
    ) -> Result<Compact, Error> {
        let mut params = Params {
            epk: None,
            apu: Vec::new(),
            apv: Vec::new(),
            iv: None,
            tag: None,
        };
        let (cek, encrypted_key) =
            <K as sealed::KeyAlg>::wrap(&self.material, E::ENC, &mut params, &mut *e)?;
        let mut iv = vec![0; E::IV_LEN];
        e.fill(&mut iv);
        let mut header = format!(r#"{{"alg":"{}","enc":"{}""#, K::ALG.name(), E::ENC.name());
        if let Some(kid) = &self.kid {
            header.push_str(&format!(
                r#","kid":{}"#,
                serde_json::to_string(kid.as_str()).unwrap_or_default()
            ));
        }
        if nested {
            //= https://www.rfc-editor.org/rfc/rfc7519#section-5.2
            //# In the case that nested signing or encryption is employed, this Header Parameter
            //# MUST be present; in this case, the value MUST be "JWT", to indicate that a Nested
            //# JWT is carried in this JWT.
            header.push_str(r#","cty":"JWT""#);
        }
        if let Some(epk) = &params.epk {
            let members: Vec<String> = members(epk)
                .into_iter()
                .map(|(name, value)| format!(r#""{name}":"{value}""#))
                .collect();
            header.push_str(&format!(r#","epk":{{{}}}"#, members.join(",")));
        }
        if let (Some(iv), Some(tag)) = (params.iv, params.tag) {
            header.push_str(&format!(
                r#","iv":"{}","tag":"{}""#,
                b64url_encode(&iv),
                b64url_encode(&tag)
            ));
        }
        header.push('}');
        let protected = b64url_encode(header.as_bytes());
        let (ciphertext, tag) =
            <E as sealed::Enc>::seal(&cek, &iv, protected.as_bytes(), plaintext)?;
        let token = format!(
            "{protected}.{}.{}.{}.{}",
            b64url_encode(&encrypted_key),
            b64url_encode(&iv),
            b64url_encode(&ciphertext),
            b64url_encode(&tag)
        );
        if token.len() > MAX_COMPACT_LEN {
            return Err(ErrorKind::TooLarge.into());
        }
        Ok(Compact(token))
    }
}

impl fmt::Debug for Jwe<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Jwe").field("kids", &self.kids).finish()
    }
}

impl fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Plaintext")
            .field("len", &self.content.expose().len())
            .finish()
    }
}

impl<K: KeyAlg> fmt::Debug for EncryptKey<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptKey")
            .field("alg", &K::ALG)
            .field("kid", &self.kid)
            .finish()
    }
}

impl<K: KeyAlg> fmt::Debug for DecryptKey<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptKey").field("alg", &K::ALG).finish()
    }
}

#[cfg(test)]
mod tests {
    use alloc::borrow::ToOwned as _;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    use base::{Entropy, SecretBytes, b64url_encode};

    use super::{DecryptKey, EncryptKey, Jwe, sealed};
    use crate::{
        A128Gcm, A128GcmKw, A128Kw, Dir, ErrorKind, Hs256, JweAlg, JweEnc, Kid, MAX_COMPACT_LEN,
        MAX_ENTRIES, MAX_JSON_LEN, SecretJwk,
    };

    #[test]
    fn names() {
        let algs = [
            "A128KW",
            "A192KW",
            "A256KW",
            "A128GCMKW",
            "A192GCMKW",
            "A256GCMKW",
            "dir",
            "ECDH-ES",
            "ECDH-ES+A128KW",
            "ECDH-ES+A192KW",
            "ECDH-ES+A256KW",
            "RSA-OAEP",
            "RSA-OAEP-256",
        ];
        let encs = [
            "A128GCM",
            "A192GCM",
            "A256GCM",
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
        ];
        for name in algs {
            let alg = JweAlg::parse(name).ok();
            assert_eq!(alg.map(JweAlg::name), Some(name));
            let json = alg.and_then(|alg| serde_json::to_string(&alg).ok());
            assert_eq!(json, Some(format!("\"{name}\"")));
            let back = json.and_then(|json| serde_json::from_str::<JweAlg>(&json).ok());
            assert_eq!(back, alg);
        }
        for name in encs {
            let enc = JweEnc::parse(name).ok();
            assert_eq!(enc.map(JweEnc::name), Some(name));
            let json = enc.and_then(|enc| serde_json::to_string(&enc).ok());
            assert_eq!(json, Some(format!("\"{name}\"")));
            let back = json.and_then(|json| serde_json::from_str::<JweEnc>(&json).ok());
            assert_eq!(back, enc);
        }
        for name in algs.into_iter().chain(encs) {
            for changed in [name.to_ascii_lowercase(), name.to_ascii_uppercase()] {
                if changed != name {
                    for kind in [
                        JweAlg::parse(&changed).err().map(|e| e.kind()),
                        JweEnc::parse(&changed).err().map(|e| e.kind()),
                    ] {
                        assert_eq!(kind, Some(ErrorKind::UnsupportedAlg), "{changed}");
                    }
                }
            }
        }
        for name in [
            "none",
            "RSA1_5",
            "PBES2-HS256+A128KW",
            "ES256K",
            "Ed25519",
            "DEF",
            "",
        ] {
            for kind in [
                JweAlg::parse(name).err().map(|e| e.kind()),
                JweEnc::parse(name).err().map(|e| e.kind()),
            ] {
                assert_eq!(kind, Some(ErrorKind::UnsupportedAlg), "{name}");
            }
            assert_eq!(
                serde_json::from_str::<JweAlg>(&format!("\"{name}\""))
                    .err()
                    .map(|e| format!("{e}")),
                Some("algorithm, curve or compression is not supported; choose an implemented one or enable its feature".into()),
                "{name}"
            );
            assert_eq!(
                serde_json::from_str::<JweEnc>(&format!("\"{name}\""))
                    .err()
                    .map(|e| format!("{e}")),
                Some("algorithm, curve or compression is not supported; choose an implemented one or enable its feature".into()),
                "{name}"
            );
        }
        // a name of the other registry is not a name of this one
        assert_eq!(
            (
                JweAlg::parse("A128GCM").err().map(|e| e.kind()),
                JweEnc::parse("A128KW").err().map(|e| e.kind())
            ),
            (
                Some(ErrorKind::UnsupportedAlg),
                Some(ErrorKind::UnsupportedAlg)
            )
        );
    }

    struct Zeros;

    impl Entropy for Zeros {
        fn fill(&mut self, out: &mut [u8]) {
            out.fill(3);
        }
    }

    fn jwk(len: usize) -> SecretJwk {
        SecretJwk::from_oct(SecretBytes::new(vec![5; len]))
    }

    fn dir() -> Option<(EncryptKey<Dir>, DecryptKey<Dir>)> {
        Some((jwk(16).encrypt_key().ok()?, jwk(16).decrypt_key().ok()?))
    }

    fn kind(wire: &str) -> Option<ErrorKind> {
        Jwe::parse(wire).err().map(|e| e.kind())
    }

    #[test]
    fn an_alg_behind_an_off_feature_skips_one_recipient_not_the_token() {
        let protected = b64url_encode(br#"{"enc":"A128GCM"}"#);
        let entry = |alg: &str| format!(r#"{{"header":{{"alg":"{alg}"}},"encrypted_key":"AA"}}"#);
        let general = |entries: &[String]| {
            format!(
                r#"{{"protected":"{protected}","recipients":[{}],"iv":"AA","ciphertext":"AA","tag":"AA"}}"#,
                entries.join(",")
            )
        };
        assert_eq!(
            json_kind(&general(&[entry("RSA-OAEP"), entry("dir")])),
            None
        );
        let off = cfg!(not(feature = "rsa-decrypt"));
        assert_eq!(
            json_kind(&general(&[entry("RSA-OAEP-256")])),
            off.then_some(ErrorKind::UnsupportedAlg)
        );
    }

    #[test]
    fn recipients_that_disagree_on_enc_are_malformed() {
        let entry = |enc: &str| format!(r#"{{"header":{{"alg":"dir","enc":"{enc}"}}}}"#);
        let wire = format!(
            r#"{{"recipients":[{},{}],"iv":"AA","ciphertext":"AA","tag":"AA"}}"#,
            entry("A128GCM"),
            entry("A256GCM")
        );
        assert_eq!(json_kind(&wire), Some(ErrorKind::Malformed));
        let same = format!(
            r#"{{"recipients":[{0},{0}],"iv":"AA","ciphertext":"AA","tag":"AA"}}"#,
            entry("A128GCM")
        );
        assert_eq!(json_kind(&same), None);
    }

    fn compact(header: &str) -> String {
        format!("{}..AA.AA.AA", b64url_encode(header.as_bytes()))
    }

    #[test]
    fn header_refusals() {
        assert_eq!(kind(&compact(r#"{"alg":"dir","enc":"A128GCM"}"#)), None);
        let cases = [
            (
                r#"{"alg":"dir","enc":"A128GCM","zip":"DEF"}"#,
                ErrorKind::UnsupportedAlg,
            ),
            (
                r#"{"alg":"dir","enc":"A128GCM","zip":null}"#,
                ErrorKind::Malformed,
            ),
            (
                r#"{"alg":"dir","enc":"A128GCM","zip":1}"#,
                ErrorKind::Malformed,
            ),
            (
                r#"{"alg":"dir","enc":"A128GCM","crit":["x"],"x":1}"#,
                ErrorKind::CriticalHeader,
            ),
            (
                r#"{"alg":"dir","enc":"A128GCM","crit":["alg"]}"#,
                ErrorKind::Malformed,
            ),
            (
                r#"{"alg":"dir","enc":"A128GCM","crit":[]}"#,
                ErrorKind::Malformed,
            ),
            (
                r#"{"alg":"dir","enc":"A128GCM","enc":"A128GCM"}"#,
                ErrorKind::DuplicateMember,
            ),
            (r#"{"alg":"dir"}"#, ErrorKind::Malformed),
            (r#"{"enc":"A128GCM"}"#, ErrorKind::Malformed),
            (r#"[1]"#, ErrorKind::Malformed),
            (
                r#"{"alg":"dir","enc":"A128GCM","epk":{"kty":"OKP","crv":"X25519","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}}"#,
                ErrorKind::UnsupportedAlg,
            ),
            (
                r#"{"alg":"dir","enc":"A128GCM","epk":{"kty":"oct","k":"AAAA"}}"#,
                ErrorKind::Malformed,
            ),
            (
                r#"{"alg":"A128GCMKW","enc":"A128GCM","iv":"AAAAAAAAAAAAAAA","tag":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
                ErrorKind::Malformed,
            ),
            (
                r#"{"alg":"A128GCMKW","enc":"A128GCM","iv":"AAAAAAAAAAAAAAAA","tag":"AAAAAAAAAAAAAAAAAAAA"}"#,
                ErrorKind::Malformed,
            ),
            (
                r#"{"alg":"A128GCMKW","enc":"A128GCM","apu":"A"}"#,
                ErrorKind::Malformed,
            ),
            (
                r#"{"alg":"A128GCMKW","enc":"A128GCM","apv":"A"}"#,
                ErrorKind::Malformed,
            ),
        ];
        for (header, want) in cases {
            assert_eq!(kind(&compact(header)), Some(want), "{header}");
        }
        let good = r#"{"alg":"A128GCMKW","enc":"A128GCM","iv":"AAAAAAAAAAAAAAAA","tag":"AAAAAAAAAAAAAAAAAAAAAA","apu":"AA","apv":"AA"}"#;
        assert_eq!(kind(&compact(good)), None);
        assert_eq!(kind("a.b.c.d"), Some(ErrorKind::Malformed));
        assert_eq!(kind("a.b.c.d.e.f"), Some(ErrorKind::Malformed));
        let header = b64url_encode(br#"{"alg":"dir","enc":"A128GCM"}"#);
        assert_eq!(
            kind(&format!("{header}..AA.AA.A")),
            Some(ErrorKind::Malformed)
        );
        assert_eq!(
            kind(&format!("{header}..AA.A=.AA")),
            Some(ErrorKind::Malformed)
        );
        let exact = format!("{header}.AA.AA.AA.{}", "A".repeat(MAX_COMPACT_LEN - 49));
        assert_eq!(exact.len(), MAX_COMPACT_LEN);
        assert_eq!(kind(&exact), None);
        let long = format!("{header}.AA.AA.AA.{}", "A".repeat(MAX_COMPACT_LEN - 48));
        assert_eq!(kind(&long), Some(ErrorKind::TooLarge));
    }

    fn json_kind(json: &str) -> Option<ErrorKind> {
        Jwe::parse_json(json.as_bytes()).err().map(|e| e.kind())
    }

    #[test]
    fn json_forms() {
        let protected = b64url_encode(br#"{"enc":"A128GCM"}"#);
        let body = r#""iv":"AA","ciphertext":"AA","tag":"AA""#;
        let recipient = r#"{"header":{"alg":"dir"}}"#;
        let general = |n: usize| {
            let entries: Vec<&str> = (0..n).map(|_| recipient).collect();
            format!(
                r#"{{"protected":"{protected}","recipients":[{}],{body}}}"#,
                entries.join(",")
            )
        };
        assert_eq!(json_kind(&general(1)), None);
        assert_eq!(json_kind(&general(MAX_ENTRIES)), None);
        assert_eq!(
            json_kind(&general(MAX_ENTRIES + 1)),
            Some(ErrorKind::TooLarge)
        );
        assert_eq!(json_kind(&general(0)), Some(ErrorKind::Malformed));
        let flat = format!(r#"{{"protected":"{protected}","header":{{"alg":"dir"}},{body}}}"#);
        assert_eq!(json_kind(&flat), None);
        let both = format!(
            r#"{{"protected":"{protected}","header":{{"alg":"dir"}},"recipients":[{recipient}],{body}}}"#
        );
        assert_eq!(json_kind(&both), Some(ErrorKind::Malformed));
        let both = format!(
            r#"{{"protected":"{protected}","encrypted_key":"AA","recipients":[{recipient}],{body}}}"#
        );
        assert_eq!(json_kind(&both), Some(ErrorKind::Malformed));
        let clash = format!(
            r#"{{"protected":"{protected}","unprotected":{{"enc":"A128GCM","alg":"dir"}},{body}}}"#
        );
        assert_eq!(json_kind(&clash), Some(ErrorKind::DuplicateMember));
        let own = format!(
            r#"{{"protected":"{protected}","unprotected":{{"alg":"dir"}},"header":{{"alg":"dir"}},{body}}}"#
        );
        assert_eq!(json_kind(&own), Some(ErrorKind::DuplicateMember));
        let crit = format!(
            r#"{{"protected":"{protected}","header":{{"alg":"dir","crit":["x"],"x":1}},{body}}}"#
        );
        assert_eq!(json_kind(&crit), Some(ErrorKind::Malformed));
        let crit = format!(
            r#"{{"protected":"{protected}","unprotected":{{"alg":"dir","crit":["x"],"x":1}},{body}}}"#
        );
        assert_eq!(json_kind(&crit), Some(ErrorKind::Malformed));
        assert_eq!(
            json_kind(&format!(r#"{{"protected":"{protected}",{body}}}"#)),
            Some(ErrorKind::Malformed)
        );
        let again =
            format!(r#"{{"protected":"{protected}","header":{{"alg":"dir"}},{body},"tag":"AA"}}"#);
        assert_eq!(json_kind(&again), Some(ErrorKind::DuplicateMember));
        let exact = format!("{flat}{}", " ".repeat(MAX_JSON_LEN - flat.len()));
        assert_eq!(json_kind(&exact), None);
        let padding = " ".repeat(MAX_JSON_LEN);
        assert_eq!(
            json_kind(&format!("{flat}{padding}")),
            Some(ErrorKind::TooLarge)
        );
        let hinted =
            format!(r#"{{"protected":"{protected}","header":{{"alg":"dir","kid":"k1"}},{body}}}"#);
        assert_eq!(
            Jwe::parse_json(hinted.as_bytes())
                .map(|j| j.kids().len())
                .ok(),
            Some(1)
        );
    }

    #[test]
    fn encrypt_and_decrypt() {
        let (encrypt, decrypt) = dir().unwrap_or_else(unreachable_keys);
        let token = encrypt.encrypt::<A128Gcm>(b"hello", &mut Zeros).ok();
        let text = token
            .as_ref()
            .map(|t| t.as_str().to_owned())
            .unwrap_or_default();
        let opened = Jwe::parse(&text).and_then(|j| j.decrypt::<Dir, A128Gcm>(&decrypt));
        assert_eq!(
            opened.as_ref().ok().map(|p| p.bytes().to_vec()),
            Some(b"hello".to_vec())
        );
        assert_eq!(opened.ok().and_then(|p| p.aad().map(<[u8]>::to_vec)), None);
        let wrong_enc =
            Jwe::parse(&text).and_then(|j| j.decrypt::<Dir, crate::A128CbcHs256>(&decrypt));
        assert_eq!(
            wrong_enc.err().map(|e| e.kind()),
            Some(ErrorKind::AlgMismatch)
        );
        let other = jwk(16).decrypt_key::<A128Kw>().ok();
        let wrong_alg = other.and_then(|k| {
            Jwe::parse(&text)
                .and_then(|j| j.decrypt::<A128Kw, A128Gcm>(&k))
                .err()
        });
        assert_eq!(wrong_alg.map(|e| e.kind()), Some(ErrorKind::AlgMismatch));
        let wrong_key = SecretJwk::from_oct(SecretBytes::new(vec![6; 16]))
            .decrypt_key::<Dir>()
            .ok();
        let failed = wrong_key.and_then(|k| {
            Jwe::parse(&text)
                .and_then(|j| j.decrypt::<Dir, A128Gcm>(&k))
                .err()
        });
        assert_eq!(failed.map(|e| e.kind()), Some(ErrorKind::Decrypt));
        let exact = encrypt
            .encrypt::<A128Gcm>(&vec![0; 12_227], &mut Zeros)
            .map(|t| t.as_str().len());
        assert_eq!(exact.ok(), Some(MAX_COMPACT_LEN));
        let over = encrypt.encrypt::<A128Gcm>(&vec![0; 12_228], &mut Zeros);
        assert_eq!(over.err().map(|e| e.kind()), Some(ErrorKind::TooLarge));
        let big = vec![0; MAX_COMPACT_LEN];
        assert_eq!(
            encrypt
                .encrypt::<A128Gcm>(&big, &mut Zeros)
                .err()
                .map(|e| e.kind()),
            Some(ErrorKind::TooLarge)
        );
        let short = SecretJwk::from_oct(SecretBytes::new(vec![5; 8]))
            .encrypt_key::<Dir>()
            .ok();
        let weak = short.and_then(|k| k.encrypt::<A128Gcm>(b"x", &mut Zeros).err());
        assert_eq!(weak.map(|e| e.kind()), Some(ErrorKind::WeakKey));
    }

    fn unreachable_keys() -> (EncryptKey<Dir>, DecryptKey<Dir>) {
        (
            EncryptKey {
                kid: None,
                material: crate::key::Public::Oct(SecretBytes::new(vec![5; 16])),
                alg: core::marker::PhantomData,
            },
            DecryptKey {
                material: crate::key::Private::Oct(SecretBytes::new(vec![5; 16])),
                alg: core::marker::PhantomData,
            },
        )
    }

    fn header_of(token: &str) -> String {
        let segment = token.split('.').next().unwrap_or_default();
        String::from_utf8(base::b64url_decode(segment).unwrap_or_default()).unwrap_or_default()
    }

    //= https://www.rfc-editor.org/rfc/rfc7519#section-5.2
    //= type=test
    //# In the case that nested signing or encryption is employed, this Header Parameter MUST be
    //# present; in this case, the value MUST be "JWT", to indicate that a Nested JWT is carried in
    //# this JWT.
    //= https://www.rfc-editor.org/rfc/rfc7519#section-7.1
    //= type=test
    //# * Else, if the JWT is a JWE, create a JWE using the Message as the plaintext for the JWE;
    //# all steps specified in [JWE] for creating a JWE MUST be followed.
    #[test]
    fn issued_headers() {
        let kid = Kid::new("k\"1").ok();
        let key = EncryptKey::<Dir> {
            kid,
            material: crate::key::Public::Oct(SecretBytes::new(vec![5; 16])),
            alg: core::marker::PhantomData,
        };
        let plain = key
            .encrypt::<A128Gcm>(b"x", &mut Zeros)
            .map(|t| header_of(t.as_str()))
            .ok();
        assert_eq!(
            plain.as_deref(),
            Some(r#"{"alg":"dir","enc":"A128GCM","kid":"k\"1"}"#)
        );
        let jws = crate::Unsigned::<Hs256>::jws(crate::Header::new(), b"{}")
            .and_then(|u| u.finish([0; 32]))
            .ok();
        let nested = jws.and_then(|t| key.encrypt_jwt::<A128Gcm>(&t, &mut Zeros).ok());
        let header = nested.as_ref().map(|t| header_of(t.as_str()));
        assert_eq!(
            header.as_deref(),
            Some(r#"{"alg":"dir","enc":"A128GCM","kid":"k\"1","cty":"JWT"}"#)
        );
        let wrapped = jwk(16)
            .encrypt_key::<A128GcmKw>()
            .ok()
            .and_then(|k| k.encrypt::<A128Gcm>(b"x", &mut Zeros).ok());
        let header = wrapped.map(|t| header_of(t.as_str())).unwrap_or_default();
        assert!(
            header.contains(r#""iv":"#) && header.contains(r#""tag":"#),
            "{header}"
        );
        let _ = <Dir as sealed::KeyAlg>::wrap;
    }

    #[test]
    fn debug_redacted() {
        let (encrypt, decrypt) = dir().unwrap_or_else(unreachable_keys);
        let token = encrypt.encrypt::<A128Gcm>(b"top secret", &mut Zeros).ok();
        let text = token
            .as_ref()
            .map(|t| t.as_str().to_owned())
            .unwrap_or_default();
        let jwe = Jwe::parse(&text).ok();
        assert!(format!("{jwe:?}").starts_with("Some(Jwe"), "{jwe:?}");
        let opened = jwe.and_then(|j| j.decrypt::<Dir, A128Gcm>(&decrypt).ok());
        let shown = format!("{opened:?}");
        assert!(
            shown.contains("len: 10") && !shown.contains("secret"),
            "{shown}"
        );
        assert!(format!("{encrypt:?}").contains("Dir") && format!("{decrypt:?}").contains("Dir"));
    }

    #[test]
    fn aad_is_authenticated() {
        let (header, aad) = (br#"{"alg":"dir","enc":"A128GCM"}"#, b"extra");
        let protected = b64url_encode(header);
        let aad_text = b64url_encode(aad);
        let cek = SecretBytes::new(vec![5; 16]);
        let sealed = <A128Gcm as sealed::Enc>::seal(
            &cek,
            &[7; 12],
            format!("{protected}.{aad_text}").as_bytes(),
            b"body",
        );
        let (ciphertext, tag) = sealed.unwrap_or_default();
        let json = |aad: &str| {
            format!(
                r#"{{"protected":"{protected}","header":{{}},"aad":"{aad}","iv":"{}","ciphertext":"{}","tag":"{}"}}"#,
                b64url_encode(&[7; 12]),
                b64url_encode(&ciphertext),
                b64url_encode(&tag)
            )
        };
        let key = jwk(16).decrypt_key::<Dir>().ok();
        let open = |text: &str| {
            let opened = key.as_ref().and_then(|k| {
                Jwe::parse_json(text.as_bytes())
                    .and_then(|j| j.decrypt::<Dir, A128Gcm>(k))
                    .ok()
            });
            opened.map(|p| (p.bytes().to_vec(), p.aad().map(<[u8]>::to_vec)))
        };
        assert_eq!(
            open(&json(&aad_text)),
            Some((b"body".to_vec(), Some(aad.to_vec())))
        );
        assert_eq!(open(&json(&b64url_encode(b"other"))), None);
    }
}
