//! HS256, HS384 and HS512 (RFC 7518 section 3.2).
use expose::Expose as _;
use hmac::{Hmac, KeyInit, Mac, digest::block_api::EagerHash};

use crate::alg::sealed;
use crate::key::{Private, Public};
use crate::{Alg, Error, ErrorKind, LocalAlg, SignAlg, SigningAlg};

/// HMAC with SHA-256.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hs256;

/// HMAC with SHA-384.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hs384;

/// HMAC with SHA-512.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Hs512;

fn mac<D: EagerHash>(key: &[u8], input: &[u8]) -> Result<Hmac<D>, Error> {
    let mut mac = Hmac::<D>::new_from_slice(key).map_err(|_| ErrorKind::WeakKey)?;
    mac.update(input);
    Ok(mac)
}

macro_rules! hs {
    ($marker:ident, $hash:ty, $alg:ident, $len:literal) => {
        impl Alg for $marker {
            const ALG: SigningAlg = SigningAlg::$alg;
            type Signature = [u8; $len];
        }

        impl SignAlg for $marker {}

        impl LocalAlg for $marker {}

        #[expect(
            private_interfaces,
            reason = "sealed: the trait is unnameable outside the crate"
        )]
        impl sealed::Alg for $marker {
            fn verify(key: &Public, input: &[u8], signature: &[u8]) -> Result<(), Error> {
                let Public::Oct(key) = key else {
                    return Err(ErrorKind::AlgMismatch.into());
                };
                mac::<$hash>(key.expose(), input)?
                    //= https://www.rfc-editor.org/rfc/rfc7518#section-3.2
                    //= type=exception
                    //= reason=the comparison is Mac::verify_slice of digest 0.11 as re-exported by hmac, which compares with subtle's ct_eq and so is constant time (NC2); no test can observe timing, so it is held by that dependency and review, not claimed as tested
                    //# The comparison of the computed HMAC value to the JWS Signature value MUST be
                    //# done in a constant-time manner to thwart timing attacks.
                    .verify_slice(signature)
                    .map_err(|_| ErrorKind::BadSignature.into())
            }
        }

        #[expect(
            private_interfaces,
            reason = "sealed: the trait is unnameable outside the crate"
        )]
        impl sealed::Local for $marker {
            fn sign(key: &Private, input: &[u8]) -> Result<[u8; $len], Error> {
                let Private::Oct(key) = key else {
                    return Err(ErrorKind::AlgMismatch.into());
                };
                Ok(mac::<$hash>(key.expose(), input)?
                    .finalize()
                    .into_bytes()
                    .into())
            }
        }
    };
}

hs!(Hs256, sha2::Sha256, Hs256, 32);
hs!(Hs384, sha2::Sha384, Hs384, 48);
hs!(Hs512, sha2::Sha512, Hs512, 64);

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use base::SecretBytes;
    use testkit::vector;
    use testkit::vectors::{Expected, Outcome, Vector, wycheproof};

    use super::{Hs256, Hs384, Hs512};
    use crate::alg::sealed::{Alg as _, Local};
    use crate::key::{Private, Public};
    use crate::{Alg, ErrorKind};

    fn hex(text: &str) -> Vec<u8> {
        let parse = |pair: &[u8; 2]| u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok();
        text.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .filter_map(parse)
            .collect()
    }

    fn sign_matches<A: Alg + Local>(file: Vector, bits: u32) {
        let tally = wycheproof(file, 30, |group, case| {
            if group.tag_size != Some(bits) || case.result != Expected::Valid {
                return Outcome::NotApplicable;
            }
            let key = Private::Oct(SecretBytes::new(hex(case
                .key
                .as_deref()
                .unwrap_or_default())));
            let message = hex(case.msg.as_deref().unwrap_or_default());
            let signed = A::sign(&key, &message).map(|tag| tag.as_ref().to_vec());
            assert_eq!(
                signed.ok(),
                Some(hex(case.tag.as_deref().unwrap_or_default()))
            );
            Outcome::Checked
        });
        assert_eq!(tally.checked(), 33);
    }

    #[test]
    fn signing_reproduces_wycheproof_tags() {
        sign_matches::<Hs256>(vector!("wycheproof/hmac_sha256_test.json"), 256);
        sign_matches::<Hs384>(vector!("wycheproof/hmac_sha384_test.json"), 384);
        sign_matches::<Hs512>(vector!("wycheproof/hmac_sha512_test.json"), 512);
    }

    #[test]
    fn only_an_oct_key_serves() {
        let secret = p256::SecretKey::from_slice(&[1; 32]).ok();
        let public = secret.as_ref().map(|k| Public::P256(k.public_key()));
        let private = secret.map(Private::P256);
        let verified = public.and_then(|k| Hs256::verify(&k, b"", &[0; 32]).err());
        assert_eq!(verified.map(|e| e.kind()), Some(ErrorKind::AlgMismatch));
        let signed = private.and_then(|k| Hs256::sign(&k, b"").err());
        assert_eq!(signed.map(|e| e.kind()), Some(ErrorKind::AlgMismatch));
    }
}
