//! ECDH-ES and ECDH-ES+A*KW on P-256, P-384 and (feature `es512`) P-521 (RFC 7518 section 4.6); no X25519.
use alloc::vec;
use alloc::vec::Vec;

use aes_gcm::KeyInit as _;
use aes_kw::{KwAes128, KwAes192, KwAes256};
use base::{Entropy, SecretBytes};
use expose::Expose as _;
use sha2::Sha256;

use crate::jwe::envelope::{Params, sealed};
use crate::key::public_of;
use crate::key::{Private, Public};
use crate::{Error, ErrorKind, JweAlg, JweEnc, KeyAlg, LocalKeyAlg, PublicKeyAlg};

/// ECDH-ES direct key agreement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EcdhEs;

/// ECDH-ES with AES-128 Key Wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EcdhEsA128Kw;

/// ECDH-ES with AES-192 Key Wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EcdhEsA192Kw;

/// ECDH-ES with AES-256 Key Wrap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EcdhEsA256Kw;

fn decrypt() -> Error {
    ErrorKind::Decrypt.into()
}

/// The shared secret `Z` of a private key and a public key on the same curve; another curve is `Decrypt`.
pub(crate) fn agree(private: &Private, public: &Public) -> Result<SecretBytes, Error> {
    macro_rules! shared {
        ($curve:ident, $secret:expr, $public:expr) => {
            SecretBytes::new(
                $curve::ecdh::diffie_hellman($secret.to_nonzero_scalar(), $public.as_affine())
                    .raw_secret_bytes()
                    .to_vec(),
            )
        };
    }
    Ok(match (private, public) {
        (Private::P256(secret), Public::P256(public)) => shared!(p256, secret, public),
        (Private::P384(secret), Public::P384(public)) => shared!(p384, secret, public),
        #[cfg(feature = "es512")]
        (Private::P521(secret), Public::P521(public)) => shared!(p521, secret, public),
        _ => return Err(decrypt()),
    })
}

/// A fresh ephemeral private key on the curve of `key`, drawn only from `e`.
fn ephemeral(key: &Public, e: &mut dyn Entropy) -> Result<Private, Error> {
    macro_rules! draw {
        ($curve:ident, $len:literal, $variant:ident, $mask:expr) => {{
            for _ in 0..64 {
                let mut bytes = [0_u8; $len];
                e.fill(&mut bytes);
                if let Some(first) = bytes.first_mut() {
                    *first &= $mask;
                }
                if let Ok(secret) = $curve::SecretKey::from_slice(&bytes) {
                    return Ok(Private::$variant(secret));
                }
            }
            Err(ErrorKind::Signer.into())
        }};
    }
    match key {
        Public::P256(_) => draw!(p256, 32, P256, 0xff),
        Public::P384(_) => draw!(p384, 48, P384, 0xff),
        #[cfg(feature = "es512")]
        Public::P521(_) => draw!(p521, 66, P521, 0x01),
        _ => Err(ErrorKind::AlgMismatch.into()),
    }
}

/// The Concat KDF key of RFC 7518 4.6.2: `algorithm` is `enc` for direct agreement and `alg` with key wrap.
fn derive(
    z: &SecretBytes,
    algorithm: &str,
    params: &Params,
    len: usize,
) -> Result<SecretBytes, Error> {
    let part = |bytes: &[u8]| -> Result<Vec<u8>, Error> {
        let size = u32::try_from(bytes.len()).map_err(|_| decrypt())?;
        Ok([size.to_be_bytes().as_slice(), bytes].concat())
    };
    let bits = u32::try_from(len * 8).map_err(|_| decrypt())?;
    let info = [
        part(algorithm.as_bytes())?,
        //= https://www.rfc-editor.org/rfc/rfc7518#section-4.6.1.2
        //# This Header Parameter MUST be understood and processed by implementations when these
        //# algorithms are used.
        part(&params.apu)?,
        //= https://www.rfc-editor.org/rfc/rfc7518#section-4.6.1.3
        //# This Header Parameter MUST be understood and processed by implementations when these
        //# algorithms are used.
        part(&params.apv)?,
        bits.to_be_bytes().to_vec(),
    ]
    .concat();
    let mut key = vec![0; len];
    one_step_kdf::derive_key_into::<Sha256>(z.expose(), &info, &mut key).map_err(|_| decrypt())?;
    Ok(SecretBytes::new(key))
}

/// How an algorithm turns the agreement into the content-encryption key: used as is, or wrapping a drawn one.
#[derive(Clone, Copy)]
enum Mode {
    Direct,
    Wrap(usize),
}

fn wrap_key(kek: &SecretBytes, cek: &[u8]) -> Result<Vec<u8>, Error> {
    let mut wrapped = vec![0; cek.len() + 8];
    let done = match kek.expose().len() {
        16 => KwAes128::new_from_slice(kek.expose())
            .map(|kw| kw.wrap_key(cek, &mut wrapped).map(|_| ())),
        24 => KwAes192::new_from_slice(kek.expose())
            .map(|kw| kw.wrap_key(cek, &mut wrapped).map(|_| ())),
        _ => KwAes256::new_from_slice(kek.expose())
            .map(|kw| kw.wrap_key(cek, &mut wrapped).map(|_| ())),
    };
    done.map_err(|_| ErrorKind::Malformed)?
        .map_err(|_| ErrorKind::Malformed)?;
    Ok(wrapped)
}

fn unwrap_key(kek: &SecretBytes, wrapped: &[u8]) -> Result<SecretBytes, Error> {
    if wrapped.len() < 24 {
        return Err(decrypt());
    }
    let mut cek = vec![0; wrapped.len() - 8];
    let done = match kek.expose().len() {
        16 => KwAes128::new_from_slice(kek.expose())
            .map(|kw| kw.unwrap_key(wrapped, &mut cek).map(|_| ())),
        24 => KwAes192::new_from_slice(kek.expose())
            .map(|kw| kw.unwrap_key(wrapped, &mut cek).map(|_| ())),
        _ => KwAes256::new_from_slice(kek.expose())
            .map(|kw| kw.unwrap_key(wrapped, &mut cek).map(|_| ())),
    };
    done.map_err(|_| decrypt())?.map_err(|_| decrypt())?;
    Ok(SecretBytes::new(cek))
}

fn wrap(
    alg: JweAlg,
    mode: Mode,
    key: &Public,
    enc: JweEnc,
    params: &mut Params,
    e: &mut dyn Entropy,
) -> Result<(SecretBytes, Vec<u8>), Error> {
    //= https://www.rfc-editor.org/rfc/rfc7518#section-4.6
    //= type=todo
    //= reason=no test compares the ephemeral keys of two agreements drawn from different entropy; the host owes fresh entropy (O1)
    //# A new ephemeral public key value MUST be generated for each key agreement operation.
    //= https://www.rfc-editor.org/rfc/rfc7518#section-4.6
    //# A new ephemeral public key value MUST be generated for each key agreement operation.
    let eph = ephemeral(key, e)?;
    //= https://www.rfc-editor.org/rfc/rfc7518#section-4.6.2
    //= type=exception
    //= reason=encrypt never sets apu or apv and decrypt does not check them for distinctness; non-goal NC9
    //# The "apu" and "apv" values MUST be distinct, when used.
    let z = agree(&eph, key)?;
    params.epk = Some(alloc::sync::Arc::new(public_of(&eph)));
    match mode {
        //= https://www.rfc-editor.org/rfc/rfc7518#section-4.6
        //# In Direct Key Agreement mode, the output of the Concat KDF MUST be a key of the same
        //# length as that used by the "enc" algorithm.
        Mode::Direct => Ok((derive(&z, enc.name(), params, enc.cek_len())?, Vec::new())),
        Mode::Wrap(len) => {
            //= https://www.rfc-editor.org/rfc/rfc7518#section-4.6
            //# In Key Agreement with Key Wrapping mode, the output of the Concat KDF MUST be a key
            //# of the length needed for the specified key wrapping algorithm.
            let kek = derive(&z, alg.name(), params, len)?;
            let mut cek = vec![0; enc.cek_len()];
            e.fill(&mut cek);
            let wrapped = wrap_key(&kek, &cek)?;
            Ok((SecretBytes::new(cek), wrapped))
        }
    }
}

fn unwrap(
    alg: JweAlg,
    mode: Mode,
    key: &Private,
    encrypted_key: &[u8],
    enc: JweEnc,
    params: &Params,
) -> Result<SecretBytes, Error> {
    //= https://www.rfc-editor.org/rfc/rfc7518#section-4.6.1.1
    //= type=todo
    //= reason=no test decrypts an ECDH-ES token whose epk is absent; appendix C proves epk is processed
    //# This Header Parameter MUST be present and MUST be understood and processed by
    //# implementations when these algorithms are used.
    //= https://www.rfc-editor.org/rfc/rfc7518#section-4.6.1.1
    //# This Header Parameter MUST be present and MUST be understood and processed by
    //# implementations when these algorithms are used.
    let epk = params.epk.as_ref().ok_or_else(decrypt)?;
    let z = agree(key, epk)?;
    match mode {
        Mode::Direct if encrypted_key.is_empty() => derive(&z, enc.name(), params, enc.cek_len()),
        Mode::Direct => Err(decrypt()),
        Mode::Wrap(len) => unwrap_key(&derive(&z, alg.name(), params, len)?, encrypted_key),
    }
}

macro_rules! ecdh {
    ($marker:ident, $alg:ident, $mode:expr) => {
        impl KeyAlg for $marker {
            const ALG: JweAlg = JweAlg::$alg;
        }

        impl PublicKeyAlg for $marker {}

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
                wrap(JweAlg::$alg, $mode, key, enc, params, e)
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
                enc: JweEnc,
                params: &Params,
            ) -> Result<SecretBytes, Error> {
                unwrap(JweAlg::$alg, $mode, key, encrypted_key, enc, params)
            }
        }
    };
}

ecdh!(EcdhEs, EcdhEs, Mode::Direct);
ecdh!(EcdhEsA128Kw, EcdhEsA128Kw, Mode::Wrap(16));
ecdh!(EcdhEsA192Kw, EcdhEsA192Kw, Mode::Wrap(24));
ecdh!(EcdhEsA256Kw, EcdhEsA256Kw, Mode::Wrap(32));

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;
    use expose::Expose as _;

    use base::{Entropy, SecretBytes};
    use serde::Deserialize;
    use testkit::vector;
    use testkit::vectors::{Json, Vector, wycheproof};

    use super::{EcdhEs, EcdhEsA128Kw, EcdhEsA192Kw, EcdhEsA256Kw, agree, derive, unwrap_key};
    use crate::jwe::envelope::{Params, sealed::KeyAlg as _, sealed::Unwrap as _};
    use crate::jwk::decode::{Key, parse};
    use crate::key::{Private, Public};
    use crate::testing::hex;
    use crate::{ErrorKind, JweEnc};

    #[derive(Deserialize)]
    struct Test {
        #[serde(rename = "tcId")]
        id: u32,
        public: Json,
        private: Json,
        shared: String,
        result: String,
    }

    #[derive(Deserialize)]
    struct Group {
        tests: Vec<Test>,
    }

    #[derive(Deserialize)]
    struct File {
        #[serde(rename = "testGroups")]
        groups: Vec<Group>,
    }

    /// Every case of `file`: a valid one agrees on the printed secret, an invalid one is refused at the key or at
    /// the agreement.
    fn file(vector: Vector, text: &str, total: usize) {
        let seen = wycheproof(vector, 1, |_, _| testkit::vectors::Outcome::Checked);
        let parsed: File = serde_json::from_str(text).unwrap_or(File { groups: Vec::new() });
        let mut checked = 0;
        for test in parsed.groups.iter().flat_map(|g| g.tests.iter()) {
            let keys = parse(test.public.text().as_bytes()).and_then(|(_, public)| {
                let (_, private) = parse(test.private.text().as_bytes())?;
                Ok((public, private))
            });
            let secret = match keys {
                Ok((Key::Public(public), Key::Private(private))) => agree(&private, &public).ok(),
                _ => None,
            };
            if test.result == "valid" {
                assert_eq!(
                    secret.map(|s| s.expose().to_vec()),
                    Some(hex(&test.shared)),
                    "{}",
                    test.id
                );
            } else {
                assert_eq!(secret.map(|s| s.expose().to_vec()), None, "{}", test.id);
            }
            checked += 1;
        }
        assert_eq!((seen.total(), checked), (total, total));
    }

    #[test]
    fn wycheproof_ecdh() {
        file(
            vector!("wycheproof/ecdh_secp256r1_webcrypto_test.json"),
            include_str!("../../../vectors/wycheproof/ecdh_secp256r1_webcrypto_test.json"),
            353,
        );
        file(
            vector!("wycheproof/ecdh_secp384r1_webcrypto_test.json"),
            include_str!("../../../vectors/wycheproof/ecdh_secp384r1_webcrypto_test.json"),
            794,
        );
        #[cfg(feature = "es512")]
        file(
            vector!("wycheproof/ecdh_secp521r1_webcrypto_test.json"),
            include_str!("../../../vectors/wycheproof/ecdh_secp521r1_webcrypto_test.json"),
            655,
        );
    }

    struct Counter(u8);

    impl Entropy for Counter {
        fn fill(&mut self, out: &mut [u8]) {
            for byte in out {
                self.0 = self.0.wrapping_mul(29).wrapping_add(5);
                *byte = self.0;
            }
        }
    }

    //= https://www.rfc-editor.org/rfc/rfc7518#section-4.6
    //= type=test
    //# In Direct Key Agreement mode, the output of the Concat KDF MUST be a key of the same length
    //# as that used by the "enc" algorithm.
    #[test]
    fn derivation_and_curves() {
        let params = Params {
            epk: None,
            apu: Vec::new(),
            apv: Vec::new(),
            iv: None,
            tag: None,
        };
        let z = SecretBytes::new(alloc::vec![7; 32]);
        let (a, b) = (
            derive(&z, "A128GCM", &params, 16).ok(),
            derive(&z, "A256GCM", &params, 16).ok(),
        );
        assert!(a.is_some() && a.as_ref().map(|k| k.expose().len()) == Some(16));
        assert_ne!(
            a.map(|k| k.expose().to_vec()),
            b.map(|k| k.expose().to_vec())
        );
        let with = Params {
            apu: alloc::vec![1],
            ..Params {
                epk: None,
                apu: Vec::new(),
                apv: alloc::vec![2],
                iv: None,
                tag: None,
            }
        };
        let (c, d) = (
            derive(&z, "A128GCM", &with, 16).ok(),
            derive(&z, "A128GCM", &params, 16).ok(),
        );
        assert_ne!(
            c.as_ref().map(|k| k.expose().to_vec()),
            d.map(|k| k.expose().to_vec())
        );
        let swapped = Params {
            apu: alloc::vec![2],
            apv: alloc::vec![1],
            ..Params {
                epk: None,
                apu: Vec::new(),
                apv: Vec::new(),
                iv: None,
                tag: None,
            }
        };
        assert_ne!(
            c.map(|k| k.expose().to_vec()),
            derive(&z, "A128GCM", &swapped, 16)
                .ok()
                .map(|k| k.expose().to_vec())
        );
        let key_p256 = p256::SecretKey::from_slice(&[1; 32]).ok();
        let key_p384 = p384::SecretKey::from_slice(&[1; 48]).ok();
        let (public256, private256) = (
            key_p256.as_ref().map(|k| Public::P256(k.public_key())),
            key_p256.map(Private::P256),
        );
        let (public384, private384) = (
            key_p384.as_ref().map(|k| Public::P384(k.public_key())),
            key_p384.map(Private::P384),
        );
        let across = private256
            .as_ref()
            .zip(public384.as_ref())
            .map(|(r, p)| agree(r, p).err().map(|e| e.kind()));
        assert_eq!(across, Some(Some(ErrorKind::Decrypt)));
        let across = private384
            .as_ref()
            .zip(public256.as_ref())
            .map(|(r, p)| agree(r, p).err().map(|e| e.kind()));
        assert_eq!(across, Some(Some(ErrorKind::Decrypt)));
        assert_eq!(
            private256
                .as_ref()
                .zip(public256.as_ref())
                .map(|(r, p)| agree(r, p).err().map(|e| e.kind())),
            Some(None)
        );
        // wrapping to a non-EC key, and unwrapping without an `epk`, are refused
        let oct = Public::Oct(SecretBytes::new(alloc::vec![0; 16]));
        let wrapped = EcdhEs::wrap(
            &oct,
            JweEnc::A128Gcm,
            &mut Params {
                epk: None,
                apu: Vec::new(),
                apv: Vec::new(),
                iv: None,
                tag: None,
            },
            &mut Counter(1),
        );
        assert_eq!(
            wrapped.err().map(|e| e.kind()),
            Some(ErrorKind::AlgMismatch)
        );
        let opened = private256.as_ref().map(|k| {
            EcdhEsA128Kw::unwrap(k, b"", JweEnc::A128Gcm, &params)
                .err()
                .map(|e| e.kind())
        });
        assert_eq!(opened, Some(Some(ErrorKind::Decrypt)));
        // an issued ephemeral key is the recipient's curve, and the three wraps take their own key sizes
        for (key, _) in [(&public256, 0), (&public384, 0)] {
            let mut p = Params {
                epk: None,
                apu: Vec::new(),
                apv: Vec::new(),
                iv: None,
                tag: None,
            };
            let made = key.as_ref().map(|k| {
                EcdhEsA192Kw::wrap(k, JweEnc::A256Gcm, &mut p, &mut Counter(2))
                    .map(|(cek, wrapped)| (cek.expose().len(), wrapped.len()))
            });
            assert_eq!(made.and_then(Result::ok), Some((32, 40)));
            assert!(p.epk.is_some());
        }
        let mut p = Params {
            epk: None,
            apu: Vec::new(),
            apv: Vec::new(),
            iv: None,
            tag: None,
        };
        let direct = public256.as_ref().map(|k| {
            EcdhEs::wrap(k, JweEnc::A128CbcHs256, &mut p, &mut Counter(3))
                .map(|(cek, wrapped)| (cek.expose().len(), wrapped.len()))
        });
        assert_eq!(direct.and_then(Result::ok), Some((32, 0)));
        let mut p = Params {
            epk: None,
            apu: Vec::new(),
            apv: Vec::new(),
            iv: None,
            tag: None,
        };
        let kw = public256.as_ref().map(|k| {
            EcdhEsA256Kw::wrap(k, JweEnc::A128Gcm, &mut p, &mut Counter(4))
                .map(|(cek, wrapped)| (cek.expose().len(), wrapped.len()))
        });
        assert_eq!(kw.and_then(Result::ok), Some((16, 24)));
    }

    //= https://www.rfc-editor.org/rfc/rfc7518#section-4.6
    //= type=test
    //# In Key Agreement with Key Wrapping mode, the output of the Concat KDF MUST be a key of the
    //# length needed for the specified key wrapping algorithm.
    #[test]
    fn key_wrap_algs_derive_their_own_key_length() {
        let secret = p256::SecretKey::from_slice(&[1; 32]).ok();
        let public = secret.as_ref().map(|k| Public::P256(k.public_key()));
        let private = secret.map(Private::P256);
        // the wrapping key is re-derived here at the RFC 7518 4.6.2 length, so a wrong length cannot open the key
        fn opens<A: crate::jwe::envelope::sealed::KeyAlg>(
            keys: Option<(&Private, &Public)>,
            name: &str,
            len: usize,
        ) -> bool {
            let Some((private, public)) = keys else {
                return false;
            };
            let mut params = blank();
            let Ok((cek, wrapped)) = A::wrap(public, JweEnc::A128Gcm, &mut params, &mut Counter(9))
            else {
                return false;
            };
            let Some(epk) = params.epk.as_deref() else {
                return false;
            };
            let kek = agree(private, epk).and_then(|z| derive(&z, name, &params, len));
            kek.and_then(|kek| unwrap_key(&kek, &wrapped))
                .is_ok_and(|opened| opened.expose() == cek.expose())
        }
        let keys = private.as_ref().zip(public.as_ref());
        assert!(opens::<EcdhEsA128Kw>(keys, "ECDH-ES+A128KW", 16));
        assert!(opens::<EcdhEsA192Kw>(keys, "ECDH-ES+A192KW", 24));
        assert!(opens::<EcdhEsA256Kw>(keys, "ECDH-ES+A256KW", 32));
        assert!(!opens::<EcdhEsA192Kw>(keys, "ECDH-ES+A192KW", 16));
    }

    fn blank() -> Params {
        Params {
            epk: None,
            apu: Vec::new(),
            apv: Vec::new(),
            iv: None,
            tag: None,
        }
    }

    #[test]
    fn wrapped_keys_have_whole_blocks() {
        let secret = p256::SecretKey::from_slice(&[1; 32]).ok();
        let public = secret.as_ref().map(|k| Public::P256(k.public_key()));
        let private = secret.map(Private::P256);
        let mut p = blank();
        let made = public
            .as_ref()
            .and_then(|k| EcdhEsA128Kw::wrap(k, JweEnc::A128Gcm, &mut p, &mut Counter(6)).ok());
        let wrapped = made.map(|(_, w)| w).unwrap_or_default();
        let outcome = |bytes: &[u8]| {
            let opened = private
                .as_ref()
                .map(|k| EcdhEsA128Kw::unwrap(k, bytes, JweEnc::A128Gcm, &p));
            opened.map(|r| r.err().map(|e| e.kind()))
        };
        let longer: Vec<u8> = wrapped.iter().copied().chain([0]).collect();
        assert_eq!(outcome(&longer), Some(Some(ErrorKind::Decrypt)));
        assert_eq!(
            outcome(wrapped.get(..16).unwrap_or_default()),
            Some(Some(ErrorKind::Decrypt))
        );
        assert_eq!(outcome(&wrapped), Some(None));
    }

    #[cfg(feature = "es512")]
    #[test]
    fn p521_keys_wrap() {
        let secret = p521::SecretKey::from_slice(&[1; 66]).ok();
        let public = secret.map(|k| Public::P521(k.public_key()));
        let mut p = blank();
        let made = public.map(|k| {
            EcdhEs::wrap(&k, JweEnc::A128Gcm, &mut p, &mut Counter(7))
                .map(|(cek, _)| cek.expose().len())
        });
        assert_eq!(made.and_then(Result::ok), Some(16));
        assert!(matches!(p.epk.as_deref(), Some(Public::P521(_))));
    }
}
