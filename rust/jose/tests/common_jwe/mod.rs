//! Helpers the JWE row files share: one `jwe_decrypt` case run under the algorithms the vector names.
use jose::{
    A128CbcHs256, A128Gcm, A128GcmKw, A128Kw, A192CbcHs384, A192Gcm, A192GcmKw, A192Kw,
    A256CbcHs512, A256Gcm, A256GcmKw, A256Kw, Dir, Enc, Error, ErrorKind, Jwe, LocalKeyAlg,
    SecretJwk,
};

/// The key-management algorithms that need no randomness to decrypt and are this file's.
pub(crate) const LOCAL: [&str; 7] = [
    "A128KW",
    "A192KW",
    "A256KW",
    "A128GCMKW",
    "A192GCMKW",
    "A256GCMKW",
    "dir",
];

fn under<K: LocalKeyAlg, E: Enc>(jwk: &str, jwe: Jwe<'_>) -> Result<Vec<u8>, Error> {
    let key = SecretJwk::decode(jwk.as_bytes())?.decrypt_key::<K>()?;
    jwe.decrypt::<K, E>(&key)
        .map(|plaintext| plaintext.bytes().to_vec())
}

fn by_enc<K: LocalKeyAlg>(enc: &str, jwk: &str, jwe: Jwe<'_>) -> Result<Vec<u8>, Error> {
    match enc {
        "A128GCM" => under::<K, A128Gcm>(jwk, jwe),
        "A192GCM" => under::<K, A192Gcm>(jwk, jwe),
        "A256GCM" => under::<K, A256Gcm>(jwk, jwe),
        "A128CBC-HS256" => under::<K, A128CbcHs256>(jwk, jwe),
        "A192CBC-HS384" => under::<K, A192CbcHs384>(jwk, jwe),
        "A256CBC-HS512" => under::<K, A256CbcHs512>(jwk, jwe),
        _ => Err(ErrorKind::UnsupportedAlg.into()),
    }
}

/// Decrypts `jwe` with the key `jwk` holds, under `alg` and `enc`; an algorithm this file does not own is
/// `UnsupportedAlg`.
pub(crate) fn decrypt(alg: &str, enc: &str, jwk: &str, jwe: Jwe<'_>) -> Result<Vec<u8>, Error> {
    match alg {
        "A128KW" => by_enc::<A128Kw>(enc, jwk, jwe),
        "A192KW" => by_enc::<A192Kw>(enc, jwk, jwe),
        "A256KW" => by_enc::<A256Kw>(enc, jwk, jwe),
        "A128GCMKW" => by_enc::<A128GcmKw>(enc, jwk, jwe),
        "A192GCMKW" => by_enc::<A192GcmKw>(enc, jwk, jwe),
        "A256GCMKW" => by_enc::<A256GcmKw>(enc, jwk, jwe),
        "dir" => by_enc::<Dir>(enc, jwk, jwe),
        _ => Err(ErrorKind::UnsupportedAlg.into()),
    }
}
