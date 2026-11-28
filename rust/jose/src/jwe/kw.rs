//! AES key wrap, AES-GCM key wrap and `dir` (RFC 7518 sections 4.4, 4.5 and 4.7).
use alloc::vec;
use alloc::vec::Vec;

use aes::cipher::consts::U12;
use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::AeadInOut as _;
use aes_gcm::{AesGcm, KeyInit as _};
use aes_kw::{KwAes128, KwAes192, KwAes256};
use base::{Entropy, SecretBytes};
use expose::Expose as _;

use crate::alg::{Params, sealed};
use crate::key::{Private, Public};
use crate::{Error, ErrorKind, JweAlg, JweEnc, KeyAlg, LocalKeyAlg};

/// AES-128 Key Wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A128Kw;

/// AES-192 Key Wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A192Kw;

/// AES-256 Key Wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A256Kw;

/// AES-128-GCM key wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A128GcmKw;

/// AES-192-GCM key wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A192GcmKw;

/// AES-256-GCM key wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A256GcmKw;

/// The shared symmetric key is the content-encryption key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Dir;

fn decrypt() -> Error {
    ErrorKind::Decrypt.into()
}

/// The symmetric key of a public or private key: any other family is `AlgMismatch`.
fn oct(key: Option<&SecretBytes>, len: usize) -> Result<&SecretBytes, Error> {
    match key {
        Some(key) if key.expose().len() == len => Ok(key),
        Some(_) => Err(ErrorKind::WeakKey.into()),
        None => Err(ErrorKind::AlgMismatch.into()),
    }
}

fn fresh(e: &mut dyn Entropy, len: usize) -> SecretBytes {
    let mut bytes = vec![0; len];
    e.fill(&mut bytes);
    SecretBytes::new(bytes)
}

macro_rules! aes_kw {
    ($marker:ident, $kw:ty, $alg:ident, $len:literal) => {
        impl KeyAlg for $marker {
            const ALG: JweAlg = JweAlg::$alg;
        }

        impl LocalKeyAlg for $marker {}

        #[expect(
            private_interfaces,
            reason = "sealed: the trait is unnameable outside the crate"
        )]
        impl sealed::KeyAlg for $marker {
            fn wrap(
                key: &Public,
                enc: JweEnc,
                _: &mut Params,
                e: &mut dyn Entropy,
            ) -> Result<(SecretBytes, Vec<u8>), Error> {
                let key = oct(
                    if let Public::Oct(k) = key {
                        Some(k)
                    } else {
                        None
                    },
                    $len,
                )?;
                let kw = <$kw>::new_from_slice(key.expose()).map_err(|_| ErrorKind::WeakKey)?;
                //= https://www.rfc-editor.org/rfc/rfc7516#section-5.1
                //# The CEK MUST have a length equal to that required for the content encryption
                //# algorithm.
                let cek = fresh(e, enc.cek_len());
                let mut wrapped = vec![0; enc.cek_len() + 8];
                kw.wrap_key(cek.expose(), &mut wrapped)
                    .map_err(|_| ErrorKind::Malformed)?;
                Ok((cek, wrapped))
            }
        }

        #[expect(
            private_interfaces,
            reason = "sealed: the trait is unnameable outside the crate"
        )]
        impl sealed::Unwrap for $marker {
            fn unwrap(
                key: &Private,
                encrypted_key: &[u8],
                _: JweEnc,
                _: &Params,
            ) -> Result<SecretBytes, Error> {
                let key = oct(
                    if let Private::Oct(k) = key {
                        Some(k)
                    } else {
                        None
                    },
                    $len,
                )?;
                let kw = <$kw>::new_from_slice(key.expose()).map_err(|_| decrypt())?;
                if encrypted_key.len() < 24 || encrypted_key.len() % 8 != 0 {
                    return Err(decrypt());
                }
                let mut cek = vec![0; encrypted_key.len() - 8];
                kw.unwrap_key(encrypted_key, &mut cek)
                    .map_err(|_| decrypt())?;
                Ok(SecretBytes::new(cek))
            }
        }
    };
}

aes_kw!(A128Kw, KwAes128, A128Kw, 16);
aes_kw!(A192Kw, KwAes192, A192Kw, 24);
aes_kw!(A256Kw, KwAes256, A256Kw, 32);

macro_rules! gcm_kw {
    ($marker:ident, $cipher:ty, $alg:ident, $len:literal) => {
        impl KeyAlg for $marker {
            const ALG: JweAlg = JweAlg::$alg;
        }

        impl LocalKeyAlg for $marker {}

        #[expect(
            private_interfaces,
            reason = "sealed: the trait is unnameable outside the crate"
        )]
        impl sealed::KeyAlg for $marker {
            fn wrap(
                key: &Public,
                enc: JweEnc,
                params: &mut Params,
                e: &mut dyn Entropy,
            ) -> Result<(SecretBytes, Vec<u8>), Error> {
                let key = oct(
                    if let Public::Oct(k) = key {
                        Some(k)
                    } else {
                        None
                    },
                    $len,
                )?;
                let cipher = AesGcm::<$cipher, U12>::new_from_slice(key.expose())
                    .map_err(|_| ErrorKind::WeakKey)?;
                let cek = fresh(e, enc.cek_len());
                let mut iv = [0; 12];
                e.fill(&mut iv);
                let mut wrapped = cek.expose().to_vec();
                let tag = cipher
                    .encrypt_inout_detached(&iv.into(), b"", wrapped.as_mut_slice().into())
                    .map_err(|_| ErrorKind::Malformed)?;
                params.iv = Some(iv);
                params.tag = Some(tag.into());
                Ok((cek, wrapped))
            }
        }

        #[expect(
            private_interfaces,
            reason = "sealed: the trait is unnameable outside the crate"
        )]
        impl sealed::Unwrap for $marker {
            fn unwrap(
                key: &Private,
                encrypted_key: &[u8],
                _: JweEnc,
                params: &Params,
            ) -> Result<SecretBytes, Error> {
                let key = oct(
                    if let Private::Oct(k) = key {
                        Some(k)
                    } else {
                        None
                    },
                    $len,
                )?;
                let cipher =
                    AesGcm::<$cipher, U12>::new_from_slice(key.expose()).map_err(|_| decrypt())?;
                //= https://www.rfc-editor.org/rfc/rfc7518#section-4.7.1.2
                //# This Header Parameter MUST be present and MUST be understood and processed by
                //# implementations when these algorithms are used.
                //= https://www.rfc-editor.org/rfc/rfc7518#section-4.7.1.1
                //# This Header Parameter MUST be present and MUST be understood and processed by
                //# implementations when these algorithms are used.
                let (Some(iv), Some(tag)) = (params.iv, params.tag) else {
                    return Err(decrypt());
                };
                let mut cek = encrypted_key.to_vec();
                cipher
                    .decrypt_inout_detached(&iv.into(), b"", cek.as_mut_slice().into(), &tag.into())
                    .map_err(|_| decrypt())?;
                Ok(SecretBytes::new(cek))
            }
        }
    };
}

gcm_kw!(A128GcmKw, Aes128, A128GcmKw, 16);
gcm_kw!(A192GcmKw, Aes192, A192GcmKw, 24);
gcm_kw!(A256GcmKw, Aes256, A256GcmKw, 32);

impl KeyAlg for Dir {
    const ALG: JweAlg = JweAlg::Dir;
}

impl LocalKeyAlg for Dir {}

#[expect(
    private_interfaces,
    reason = "sealed: the trait is unnameable outside the crate"
)]
impl sealed::KeyAlg for Dir {
    fn wrap(
        key: &Public,
        enc: JweEnc,
        _: &mut Params,
        _: &mut dyn Entropy,
    ) -> Result<(SecretBytes, Vec<u8>), Error> {
        let key = oct(
            if let Public::Oct(k) = key {
                Some(k)
            } else {
                None
            },
            enc.cek_len(),
        )?;
        Ok((SecretBytes::new(key.expose().to_vec()), Vec::new()))
    }
}

#[expect(
    private_interfaces,
    reason = "sealed: the trait is unnameable outside the crate"
)]
impl sealed::Unwrap for Dir {
    fn unwrap(
        key: &Private,
        encrypted_key: &[u8],
        enc: JweEnc,
        _: &Params,
    ) -> Result<SecretBytes, Error> {
        if !encrypted_key.is_empty() {
            return Err(decrypt());
        }
        let key = oct(
            if let Private::Oct(k) = key {
                Some(k)
            } else {
                None
            },
            enc.cek_len(),
        )
        .map_err(|_| decrypt())?;
        Ok(SecretBytes::new(key.expose().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;
    use expose::Expose as _;

    use base::{Entropy, SecretBytes};
    use serde::Deserialize;
    use testkit::vector;
    use testkit::vectors::{Outcome, wycheproof};

    use super::{A128GcmKw, A128Kw, A192GcmKw, A192Kw, A256GcmKw, A256Kw, Dir};
    use crate::alg::{Params, sealed::KeyAlg as _, sealed::Unwrap as _};
    use crate::key::{Private, Public};
    use crate::testing::hex;
    use crate::{ErrorKind, JweEnc, SecretJwk};

    /// Hands out one fixed byte string, as the key to wrap.
    struct Fixed(Vec<u8>);

    impl Entropy for Fixed {
        fn fill(&mut self, out: &mut [u8]) {
            for (slot, byte) in out.iter_mut().zip(self.0.iter()) {
                *slot = *byte;
            }
        }
    }

    fn params() -> Params {
        Params {
            epk: None,
            apu: Vec::new(),
            apv: Vec::new(),
            iv: None,
            tag: None,
        }
    }

    #[derive(Deserialize)]
    struct Test {
        #[serde(rename = "tcId")]
        id: u32,
        key: String,
        msg: String,
        ct: String,
        result: String,
    }

    #[derive(Deserialize)]
    struct Group {
        #[serde(rename = "keySize")]
        key_size: u32,
        tests: Vec<Test>,
    }

    #[derive(Deserialize)]
    struct File {
        #[serde(rename = "testGroups")]
        groups: Vec<Group>,
    }

    /// The wrap of `cek` under `key` and the unwrap of `wrapped`, through the algorithm the key's size names.
    fn both(
        size: u32,
        key: &[u8],
        cek: &[u8],
        wrapped: &[u8],
    ) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        let (public, private) = (
            Public::Oct(SecretBytes::new(key.to_vec())),
            Private::Oct(SecretBytes::new(key.to_vec())),
        );
        let enc = match cek.len() {
            16 => JweEnc::A128Gcm,
            24 => JweEnc::A192Gcm,
            _ => JweEnc::A256Gcm,
        };
        let mut fixed = Fixed(cek.to_vec());
        let wrap = |alg: &mut dyn FnMut() -> Result<(SecretBytes, Vec<u8>), crate::Error>| {
            alg().ok().map(|(_, wrapped)| wrapped)
        };
        let (wrapped_by, unwrapped_by) = match size {
            128 => (
                wrap(&mut || A128Kw::wrap(&public, enc, &mut params(), &mut fixed)),
                A128Kw::unwrap(&private, wrapped, enc, &params()).ok(),
            ),
            192 => (
                wrap(&mut || A192Kw::wrap(&public, enc, &mut params(), &mut fixed)),
                A192Kw::unwrap(&private, wrapped, enc, &params()).ok(),
            ),
            _ => (
                wrap(&mut || A256Kw::wrap(&public, enc, &mut params(), &mut fixed)),
                A256Kw::unwrap(&private, wrapped, enc, &params()).ok(),
            ),
        };
        (wrapped_by, unwrapped_by.map(|cek| cek.expose().to_vec()))
    }

    #[test]
    fn wycheproof_kw() {
        let seen = wycheproof(vector!("wycheproof/aes_wrap_test.json"), 1, |_, _| {
            Outcome::Checked
        });
        let parsed: File = serde_json::from_str(include_str!(
            "../../../vectors/wycheproof/aes_wrap_test.json"
        ))
        .unwrap_or(File { groups: Vec::new() });
        let (mut checked, mut skipped) = (0, 0);
        for group in &parsed.groups {
            for test in &group.tests {
                if test.result == "acceptable" {
                    skipped += 1;
                    continue;
                }
                let (key, cek, wrapped) = (hex(&test.key), hex(&test.msg), hex(&test.ct));
                let (wrapped_by, unwrapped_by) = both(group.key_size, &key, &cek, &wrapped);
                if test.result == "valid" {
                    assert_eq!(unwrapped_by, Some(cek.clone()), "{}", test.id);
                    // only a content-encryption key of an AES length is drawn whole
                    if [16, 24, 32].contains(&cek.len()) {
                        assert_eq!(wrapped_by, Some(wrapped), "{}", test.id);
                    }
                } else {
                    assert_eq!(unwrapped_by, None, "{}", test.id);
                }
                checked += 1;
            }
        }
        assert_eq!(seen.total(), checked + skipped);
        assert!(checked > 100 && skipped == 3, "{checked} {skipped}");
    }

    #[test]
    fn lengths() {
        let key = |len: usize| SecretJwk::from_oct(SecretBytes::new(alloc::vec![1; len]));
        let kind = |r: Result<(), crate::Error>| r.err().map(|e| e.kind());
        assert_eq!(kind(key(16).encrypt_key::<A128Kw>().map(|_| ())), None);
        assert_eq!(
            kind(key(15).encrypt_key::<A128Kw>().map(|_| ())),
            Some(ErrorKind::WeakKey)
        );
        assert_eq!(kind(key(24).decrypt_key::<A192Kw>().map(|_| ())), None);
        assert_eq!(
            kind(key(16).decrypt_key::<A192GcmKw>().map(|_| ())),
            Some(ErrorKind::WeakKey)
        );
        assert_eq!(kind(key(32).decrypt_key::<A256GcmKw>().map(|_| ())), None);
        assert_eq!(kind(key(32).encrypt_key::<A256Kw>().map(|_| ())), None);
        assert_eq!(kind(key(16).encrypt_key::<A128GcmKw>().map(|_| ())), None);
        assert_eq!(kind(key(7).encrypt_key::<Dir>().map(|_| ())), None);
        assert_eq!(
            kind(key(16).encrypt_key::<A256Kw>().map(|_| ())),
            Some(ErrorKind::WeakKey)
        );
        assert_eq!(
            kind(key(16).encrypt_key::<A256GcmKw>().map(|_| ())),
            Some(ErrorKind::WeakKey)
        );
        assert_eq!(
            kind(key(24).encrypt_key::<A128GcmKw>().map(|_| ())),
            Some(ErrorKind::WeakKey)
        );
        assert_eq!(
            kind(key(16).encrypt_key::<A192Kw>().map(|_| ())),
            Some(ErrorKind::WeakKey)
        );
        let wrong = Public::Oct(SecretBytes::new(alloc::vec![0; 16]));
        let mut fixed = Fixed(alloc::vec![9; 32]);
        let wrapped = <Dir as crate::alg::sealed::KeyAlg>::wrap(
            &wrong,
            JweEnc::A256Gcm,
            &mut params(),
            &mut fixed,
        );
        assert_eq!(wrapped.err().map(|e| e.kind()), Some(ErrorKind::WeakKey));
        let opened = Dir::unwrap(
            &Private::Oct(SecretBytes::new(alloc::vec![0; 16])),
            b"",
            JweEnc::A256Gcm,
            &params(),
        );
        assert_eq!(opened.err().map(|e| e.kind()), Some(ErrorKind::Decrypt));
    }
}
