//! RSA-OAEP and RSA-OAEP-256 (RFC 7518 section 4.3), feature `rsa-decrypt`: one decryption path, a random CEK on OAEP failure.
use alloc::vec;
use alloc::vec::Vec;
use base::{Entropy, SecretBytes};
use rsa::Oaep;

use crate::jwe::envelope::{Params, sealed};
use crate::key::{Private, Public};
use crate::rng::Source;
use crate::{BlindedKeyAlg, Error, ErrorKind, JweAlg, JweEnc, KeyAlg, PublicKeyAlg};

/// RSAES-OAEP with SHA-1 and MGF1 with SHA-1 (feature `rsa-decrypt`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RsaOaep;

/// RSAES-OAEP with SHA-256 and MGF1 with SHA-256 (feature `rsa-decrypt`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RsaOaep256;

macro_rules! oaep {
    ($marker:ident, $alg:ident, $digest:ty) => {
        impl KeyAlg for $marker {
            const ALG: JweAlg = JweAlg::$alg;
        }

        impl PublicKeyAlg for $marker {}

        impl BlindedKeyAlg for $marker {}

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
                let Public::Rsa(key) = key else {
                    return Err(ErrorKind::AlgMismatch.into());
                };
                let mut cek = vec![0; enc.cek_len()];
                e.fill(&mut cek);
                let wrapped = key
                    .encrypt(&mut Source(e), Oaep::<$digest>::new(), &cek)
                    .map_err(|_| ErrorKind::Malformed)?;
                Ok((SecretBytes::new(cek), wrapped))
            }
        }

        impl $marker {
            /// The message OAEP opens `ciphertext` to, blinded from `e`; none for any failure.
            fn open(key: &Private, ciphertext: &[u8], e: &mut dyn Entropy) -> Option<Vec<u8>> {
                let Private::Rsa(key) = key else {
                    return None;
                };
                key.decrypt_blinded(&mut Source(e), Oaep::<$digest>::new(), ciphertext)
                    .ok()
            }
        }

        #[expect(
            private_interfaces,
            reason = "sealed: the trait is unnameable outside the crate"
        )]
        impl sealed::BlindedUnwrap for $marker {
            fn unwrap(
                key: &Private,
                encrypted_key: &[u8],
                enc: JweEnc,
                e: &mut dyn Entropy,
            ) -> SecretBytes {
                let opened = Self::open(key, encrypted_key, &mut *e)
                    .filter(|cek| cek.len() == enc.cek_len());
                // one path: the substitute is drawn whether or not it is used
                let mut substitute = vec![0; enc.cek_len()];
                e.fill(&mut substitute);
                SecretBytes::new(opened.unwrap_or(substitute))
            }
        }
    };
}

oaep!(RsaOaep, RsaOaep, sha1::Sha1);
oaep!(RsaOaep256, RsaOaep256, sha2::Sha256);

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;
    use expose::Expose as _;

    use serde::Deserialize;
    use testkit::vector;
    use testkit::vectors::{Json, Outcome, Vector, wycheproof};

    use super::{RsaOaep, RsaOaep256};
    use crate::JweEnc;
    use crate::jwe::envelope::sealed::BlindedUnwrap as _;
    use crate::jwk::decode::{Key, parse};
    use crate::key::Private;
    use crate::testing::hex;

    #[derive(Deserialize)]
    struct Test {
        #[serde(rename = "tcId")]
        id: u32,
        comment: String,
        msg: String,
        ct: String,
        label: String,
        result: String,
    }

    #[derive(Deserialize)]
    struct Group {
        #[serde(rename = "privateKeyJwk")]
        key: Json,
        tests: Vec<Test>,
    }

    #[derive(Deserialize)]
    struct File {
        #[serde(rename = "testGroups")]
        groups: Vec<Group>,
    }

    /// An OAEP file with the empty label JWE uses: a valid case opens to its message and an invalid one is `None`;
    /// the other labels are not applicable.
    fn file(vector: Vector, text: &str, sha1: bool, total: usize) {
        let seen = wycheproof(vector, 1, |_, _| Outcome::Checked);
        let parsed: File = serde_json::from_str(text).unwrap_or(File { groups: Vec::new() });
        let (mut checked, mut skipped, mut deviating) = (0, 0, 0);
        for group in &parsed.groups {
            let key = parse(group.key.text().as_bytes())
                .ok()
                .and_then(|(_, key)| match key {
                    Key::Private(key) => Some(key),
                    Key::Public(_) => None,
                });
            assert!(key.is_some());
            for test in &group.tests {
                if !test.label.is_empty() {
                    skipped += 1;
                    continue;
                }
                let ct = hex(&test.ct);
                let opened = key.as_ref().and_then(|k| {
                    if sha1 {
                        RsaOaep::open(k, &ct, &mut testkit::seeded(1))
                    } else {
                        RsaOaep256::open(k, &ct, &mut testkit::seeded(1))
                    }
                });
                // a known deviation of the `rsa` dependency (NC2): it opens these where the vector says invalid
                if test.comment == "First byte is 1" {
                    assert!(opened.is_some(), "{}", test.id);
                    deviating += 1;
                    continue;
                }
                let want = (test.result == "valid").then(|| hex(&test.msg));
                assert_eq!(opened, want, "{}", test.id);
                checked += 1;
            }
        }
        assert_eq!(deviating, 1);
        assert_eq!(seen.total(), total);
        assert_eq!(checked + skipped + deviating, total);
    }

    #[test]
    fn wycheproof_oaep() {
        file(
            vector!("wycheproof/rsa_oaep_2048_sha1_mgf1sha1_test.json"),
            include_str!("../../../vectors/wycheproof/rsa_oaep_2048_sha1_mgf1sha1_test.json"),
            true,
            36,
        );
        file(
            vector!("wycheproof/rsa_oaep_2048_sha256_mgf1sha256_test.json"),
            include_str!("../../../vectors/wycheproof/rsa_oaep_2048_sha256_mgf1sha256_test.json"),
            false,
            37,
        );
        file(
            vector!("wycheproof/rsa_oaep_3072_sha256_mgf1sha256_test.json"),
            include_str!("../../../vectors/wycheproof/rsa_oaep_3072_sha256_mgf1sha256_test.json"),
            false,
            37,
        );
        file(
            vector!("wycheproof/rsa_oaep_4096_sha256_mgf1sha256_test.json"),
            include_str!("../../../vectors/wycheproof/rsa_oaep_4096_sha256_mgf1sha256_test.json"),
            false,
            37,
        );
    }

    /// An OAEP failure and a success both return a key of the right length, and the failure's is the entropy's.
    #[test]
    fn one_path() {
        let parsed: File = serde_json::from_str(include_str!(
            "../../../vectors/wycheproof/rsa_oaep_2048_sha256_mgf1sha256_test.json"
        ))
        .unwrap_or(File { groups: Vec::new() });
        let key = parsed
            .groups
            .first()
            .and_then(|g| parse(g.key.text().as_bytes()).ok());
        let key: Option<Private> = key.and_then(|(_, key)| match key {
            Key::Private(key) => Some(key),
            Key::Public(_) => None,
        });
        let tests = parsed
            .groups
            .first()
            .map(|g| g.tests.as_slice())
            .unwrap_or_default();
        let invalid = tests
            .iter()
            .find(|t| t.result == "invalid")
            .map(|t| hex(&t.ct))
            .unwrap_or_default();
        // a valid ciphertext whose message is not 16 bytes is also a failure of the JWE kind
        let cek = |ct: &[u8], seed: u8| {
            key.as_ref().map(|k| {
                RsaOaep256::unwrap(
                    k,
                    ct,
                    JweEnc::A128Gcm,
                    &mut testkit::seeded(u64::from(seed)),
                )
                .expose()
                .to_vec()
            })
        };
        let (one, again, other) = (cek(&invalid, 1), cek(&invalid, 1), cek(&invalid, 2));
        assert_eq!(one.as_ref().map(Vec::len), Some(16));
        assert_eq!(one, again);
        assert_ne!(one, other);
        assert_eq!(cek(&[1, 2, 3], 1).map(|k| k.len()), Some(16));
        let wrong = Private::Oct(base::SecretBytes::new(alloc::vec![1; 16]));
        let other = RsaOaep256::unwrap(&wrong, &invalid, JweEnc::A128Gcm, &mut testkit::seeded(1));
        assert_eq!(other.expose().len(), 16);
    }
}
