//! AES-GCM and AES-CBC with HMAC-SHA-2 content encryption (RFC 7518 sections 5.2 and 5.3).
use alloc::vec::Vec;

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::consts::U12;
use aes::cipher::{BlockModeDecrypt as _, BlockModeEncrypt as _, KeyIvInit as _};
use aes::{Aes128, Aes192, Aes256};
use aes_gcm::aead::AeadInOut as _;
use aes_gcm::{AesGcm, KeyInit as _};
use base::SecretBytes;
use expose::Expose as _;
use hmac::{Hmac, Mac as _};
use sha2::{Sha256, Sha384, Sha512};

use crate::jwe::envelope::sealed;
use crate::{Enc, Error, ErrorKind, JweEnc};

/// AES-128-GCM.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A128Gcm;

/// AES-192-GCM.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A192Gcm;

/// AES-256-GCM.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A256Gcm;

/// AES-128-CBC with HMAC SHA-256, the tag truncated to 128 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A128CbcHs256;

/// AES-192-CBC with HMAC SHA-384, the tag truncated to 192 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A192CbcHs384;

/// AES-256-CBC with HMAC SHA-512, the tag truncated to 256 bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct A256CbcHs512;

fn decrypt() -> Error {
    ErrorKind::Decrypt.into()
}

macro_rules! gcm {
    ($marker:ident, $cipher:ty, $enc:ident, $key:literal) => {
        impl Enc for $marker {
            const ENC: JweEnc = JweEnc::$enc;
        }
        impl sealed::Enc for $marker {
            const CEK_LEN: usize = $key;
            const IV_LEN: usize = 12;

            fn seal(
                cek: &SecretBytes,
                iv: &[u8],
                aad: &[u8],
                plaintext: &[u8],
            ) -> Result<(Vec<u8>, Vec<u8>), Error> {
                let cipher = AesGcm::<$cipher, U12>::new_from_slice(cek.expose())
                    .map_err(|_| ErrorKind::WeakKey)?;
                let nonce = iv.try_into().map_err(|_| ErrorKind::Malformed)?;
                let mut buffer = plaintext.to_vec();
                let tag = cipher
                    .encrypt_inout_detached(&nonce, aad, buffer.as_mut_slice().into())
                    .map_err(|_| ErrorKind::Malformed)?;
                Ok((buffer, tag.to_vec()))
            }

            fn open(
                cek: &SecretBytes,
                iv: &[u8],
                aad: &[u8],
                ciphertext: &[u8],
                tag: &[u8],
            ) -> Result<SecretBytes, Error> {
                let cipher =
                    AesGcm::<$cipher, U12>::new_from_slice(cek.expose()).map_err(|_| decrypt())?;
                let (nonce, tag) = (
                    iv.try_into().map_err(|_| decrypt())?,
                    tag.try_into().map_err(|_| decrypt())?,
                );
                let mut buffer = ciphertext.to_vec();
                cipher
                    .decrypt_inout_detached(&nonce, aad, buffer.as_mut_slice().into(), &tag)
                    .map_err(|_| decrypt())?;
                Ok(SecretBytes::new(buffer))
            }
        }
    };
}

gcm!(A128Gcm, Aes128, A128Gcm, 16);
gcm!(A192Gcm, Aes192, A192Gcm, 24);
gcm!(A256Gcm, Aes256, A256Gcm, 32);

/// The MAC over `aad || iv || ciphertext || AL`, `AL` the AAD length in bits as 64 bits (RFC 7518 5.2.2.1).
fn mac<D: hmac::digest::block_api::EagerHash>(
    key: &[u8],
    aad: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Hmac<D>, Error> {
    let mut mac = Hmac::<D>::new_from_slice(key).map_err(|_| decrypt())?;
    let bits = u64::try_from(aad.len())
        .map_err(|_| decrypt())?
        .saturating_mul(8);
    for part in [aad, iv, ciphertext, &bits.to_be_bytes()] {
        mac.update(part);
    }
    Ok(mac)
}

macro_rules! cbc_hmac {
    ($marker:ident, $cipher:ty, $hash:ty, $enc:ident, $key:literal) => {
        impl Enc for $marker {
            const ENC: JweEnc = JweEnc::$enc;
        }
        impl sealed::Enc for $marker {
            const CEK_LEN: usize = $key;
            const IV_LEN: usize = 16;

            fn seal(
                cek: &SecretBytes,
                iv: &[u8],
                aad: &[u8],
                plaintext: &[u8],
            ) -> Result<(Vec<u8>, Vec<u8>), Error> {
                let (mac_key, enc_key) = cek
                    .expose()
                    .split_at_checked($key / 2)
                    .ok_or(ErrorKind::WeakKey)?;
                let encryptor = cbc::Encryptor::<$cipher>::new_from_slices(enc_key, iv)
                    .map_err(|_| ErrorKind::Malformed)?;
                let ciphertext = encryptor.encrypt_padded_vec::<Pkcs7>(plaintext);
                let tag = mac::<$hash>(mac_key, aad, iv, &ciphertext)?
                    .finalize()
                    .into_bytes();
                Ok((ciphertext, tag.get(..$key / 2).unwrap_or_default().to_vec()))
            }

            /// The tag is checked, in constant time, before any decryption.
            fn open(
                cek: &SecretBytes,
                iv: &[u8],
                aad: &[u8],
                ciphertext: &[u8],
                tag: &[u8],
            ) -> Result<SecretBytes, Error> {
                let (mac_key, enc_key) = cek
                    .expose()
                    .split_at_checked($key / 2)
                    .ok_or_else(decrypt)?;
                if tag.len() != $key / 2 {
                    return Err(decrypt());
                }
                mac::<$hash>(mac_key, aad, iv, ciphertext)?
                    .verify_truncated_left(tag)
                    .map_err(|_| decrypt())?;
                let decryptor = cbc::Decryptor::<$cipher>::new_from_slices(enc_key, iv)
                    .map_err(|_| decrypt())?;
                let plaintext = decryptor
                    .decrypt_padded_vec::<Pkcs7>(ciphertext)
                    .map_err(|_| decrypt())?;
                Ok(SecretBytes::new(plaintext))
            }
        }
    };
}

cbc_hmac!(A128CbcHs256, Aes128, Sha256, A128CbcHs256, 32);
cbc_hmac!(A192CbcHs384, Aes192, Sha384, A192CbcHs384, 48);
cbc_hmac!(A256CbcHs512, Aes256, Sha512, A256CbcHs512, 64);

impl JweEnc {
    /// The content-encryption key length of this algorithm in bytes.
    pub(crate) const fn cek_len(self) -> usize {
        match self {
            Self::A128Gcm => 16,
            Self::A192Gcm => 24,
            Self::A256Gcm | Self::A128CbcHs256 => 32,
            Self::A192CbcHs384 => 48,
            Self::A256CbcHs512 => 64,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;
    use expose::Expose as _;

    use base::SecretBytes;
    use serde::Deserialize;
    use testkit::vector;
    use testkit::vectors::{Json, Outcome, Vector, run, wycheproof};

    use hmac::Mac as _;
    use hmac::digest::block_api::EagerHash;
    use sha2::{Sha256, Sha384, Sha512};

    use super::{A128CbcHs256, A128Gcm, A192CbcHs384, A192Gcm, A256CbcHs512, A256Gcm, mac};
    use crate::jwe::envelope::sealed::Enc as Sealed;
    use crate::testing::hex;
    use crate::{ErrorKind, JweEnc};

    #[derive(Deserialize)]
    struct Expect {
        ok: bool,
        ciphertext: Option<String>,
        tag: Option<String>,
        plaintext: Option<String>,
    }

    #[derive(Deserialize)]
    struct Case {
        id: String,
        enc: String,
        key: String,
        iv: String,
        aad: String,
        plaintext: Option<String>,
        ciphertext: Option<String>,
        tag: Option<String>,
        expect: Expect,
    }

    fn appendix_b<E: Sealed>(case: &Case) {
        let (cek, iv, aad) = (
            SecretBytes::new(hex(&case.key)),
            hex(&case.iv),
            hex(&case.aad),
        );
        if let Some(plaintext) = &case.plaintext {
            let sealed = E::seal(&cek, &iv, &aad, &hex(plaintext)).ok();
            let want = (
                case.expect.ciphertext.as_deref().map(hex),
                case.expect.tag.as_deref().map(hex),
            );
            assert_eq!(
                (sealed.as_ref().map(|s| s.0.clone()), sealed.map(|s| s.1)),
                want,
                "{}",
                case.id
            );
        } else {
            let opened = E::open(
                &cek,
                &iv,
                &aad,
                &hex(case.ciphertext.as_deref().unwrap_or_default()),
                &hex(case.tag.as_deref().unwrap_or_default()),
            );
            assert_eq!(opened.is_ok(), case.expect.ok, "{}", case.id);
            if let Some(want) = &case.expect.plaintext {
                assert_eq!(
                    opened.ok().map(|p| p.expose().to_vec()),
                    Some(hex(want)),
                    "{}",
                    case.id
                );
            } else {
                assert_eq!(
                    opened.err().map(|e| e.kind()),
                    Some(ErrorKind::Decrypt),
                    "{}",
                    case.id
                );
            }
        }
    }

    #[test]
    fn rfc7518_b() {
        let tally = run::<Case>(vector!("rfc7518/appendix-b.json"), 15, |case| {
            match case.enc.as_str() {
                "A128CBC-HS256" => appendix_b::<A128CbcHs256>(case),
                "A192CBC-HS384" => appendix_b::<A192CbcHs384>(case),
                _ => appendix_b::<A256CbcHs512>(case),
            }
            Outcome::Checked
        });
        assert_eq!((tally.total(), tally.checked()), (15, 15));
    }

    #[derive(Deserialize)]
    struct Test {
        #[serde(rename = "tcId")]
        id: u32,
        key: String,
        iv: String,
        aad: String,
        msg: String,
        ct: String,
        tag: String,
        result: String,
    }

    #[derive(Deserialize)]
    struct Group {
        #[serde(rename = "keySize")]
        key_size: u32,
        #[serde(rename = "ivSize")]
        iv_size: u32,
        #[serde(rename = "tagSize")]
        tag_size: u32,
        tests: Vec<Test>,
    }

    #[derive(Deserialize)]
    struct File {
        #[serde(rename = "testGroups")]
        groups: Vec<Group>,
    }

    /// Every case of the file, read through the runner that checks its hash and count, then once more for the
    /// fields the typed reader does not carry; `tag_bits` is the tag the algorithm writes, other groups are
    /// not applicable.
    fn aead<E: Sealed>(file: Vector, text: &str, tag_bits: u32) -> (usize, usize) {
        let seen = wycheproof(file, 1, |_, _| Outcome::Checked);
        let parsed: File = serde_json::from_str(text).unwrap_or(File { groups: Vec::new() });
        let (mut checked, mut skipped) = (0, 0);
        for group in &parsed.groups {
            if group.key_size != 8 * u32::try_from(E::CEK_LEN).unwrap_or(0)
                || group.iv_size != 8 * u32::try_from(E::IV_LEN).unwrap_or(0)
                || group.tag_size != tag_bits
            {
                skipped += group.tests.len();
                continue;
            }
            for test in &group.tests {
                let (cek, iv, aad) = (
                    SecretBytes::new(hex(&test.key)),
                    hex(&test.iv),
                    hex(&test.aad),
                );
                let (msg, ct, tag) = (hex(&test.msg), hex(&test.ct), hex(&test.tag));
                let opened = E::open(&cek, &iv, &aad, &ct, &tag);
                assert_eq!(opened.is_ok(), test.result != "invalid", "{}", test.id);
                if test.result == "valid" {
                    assert_eq!(
                        opened.ok().map(|p| p.expose().to_vec()),
                        Some(msg.clone()),
                        "{}",
                        test.id
                    );
                    assert_eq!(
                        E::seal(&cek, &iv, &aad, &msg).ok(),
                        Some((ct, tag)),
                        "{}",
                        test.id
                    );
                }
                checked += 1;
            }
        }
        assert_eq!(seen.total(), checked + skipped);
        (checked, skipped)
    }

    #[test]
    fn wycheproof_aead() {
        let gcm = include_str!("../../../vectors/wycheproof/aes_gcm_test.json");
        let counts = [
            aead::<A128Gcm>(vector!("wycheproof/aes_gcm_test.json"), gcm, 128),
            aead::<A192Gcm>(vector!("wycheproof/aes_gcm_test.json"), gcm, 128),
            aead::<A256Gcm>(vector!("wycheproof/aes_gcm_test.json"), gcm, 128),
        ];
        assert!(
            counts.iter().all(|(checked, _)| *checked > 20),
            "{counts:?}"
        );
        let cbc = [
            aead::<A128CbcHs256>(
                vector!("wycheproof/a128cbc_hs256_test.json"),
                include_str!("../../../vectors/wycheproof/a128cbc_hs256_test.json"),
                128,
            ),
            aead::<A192CbcHs384>(
                vector!("wycheproof/a192cbc_hs384_test.json"),
                include_str!("../../../vectors/wycheproof/a192cbc_hs384_test.json"),
                192,
            ),
            aead::<A256CbcHs512>(
                vector!("wycheproof/a256cbc_hs512_test.json"),
                include_str!("../../../vectors/wycheproof/a256cbc_hs512_test.json"),
                256,
            ),
        ];
        assert_eq!(cbc, [(94, 0); 3]);
        let _ = (Json::text, JweEnc::A128Gcm);
    }

    /// Bad tag, bad padding and both at once are the one `Decrypt`: the padding is never reached on a bad tag.
    fn tag_first_for<E: Sealed, D: EagerHash>() {
        let cek = SecretBytes::new(
            (0..E::CEK_LEN)
                .map(|i| u8::try_from(i).unwrap_or(0))
                .collect(),
        );
        let (iv, aad) = ([7u8; 16], b"header".to_vec());
        let sealed = E::seal(&cek, &iv, &aad, b"attack at dawn").ok();
        let (ciphertext, tag) = sealed.unwrap_or_default();
        assert!(!tag.is_empty());
        let open =
            |ct: &[u8], tag: &[u8]| E::open(&cek, &iv, &aad, ct, tag).err().map(|e| e.kind());
        assert_eq!(open(&ciphertext, &tag), None);
        let mut bad_tag = tag.clone();
        if let Some(byte) = bad_tag.last_mut() {
            *byte ^= 1;
        }
        // not a block multiple, then a block of bytes that is not padded text
        let ragged = [ciphertext.clone(), vec![1]].concat();
        let unpadded = vec![0u8; 16];
        let (mac_key, _) = cek.expose().split_at(E::CEK_LEN / 2);
        let valid_tag = |ct: &[u8]| {
            let full = mac::<D>(mac_key, &aad, &iv, ct).map(|m| m.finalize().into_bytes());
            full.map(|t| t.get(..E::CEK_LEN / 2).unwrap_or_default().to_vec())
                .unwrap_or_default()
        };
        for bad_body in [&ragged, &unpadded] {
            // a tag that verifies over a body that does not decrypt, and a tag that does not verify
            assert_eq!(
                open(bad_body, &valid_tag(bad_body)),
                Some(ErrorKind::Decrypt)
            );
            assert_eq!(open(bad_body, &bad_tag), Some(ErrorKind::Decrypt));
        }
        assert_eq!(open(&ciphertext, &bad_tag), Some(ErrorKind::Decrypt));
        assert_eq!(open(&ciphertext, &tag[1..]), Some(ErrorKind::Decrypt));
    }

    #[test]
    fn tag_first() {
        tag_first_for::<A128CbcHs256, Sha256>();
        tag_first_for::<A192CbcHs384, Sha384>();
        tag_first_for::<A256CbcHs512, Sha512>();
    }
}
