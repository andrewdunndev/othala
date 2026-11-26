//! Helpers the row files share: one `jws_verify` case run under the algorithm and key the vector names.
use jose::{
    Alg, EdDsa, Error, Es256, Es384, Hs256, Hs384, Hs512, Jwk, Jws, Ps256, Ps384, Ps512, Rs256,
    Rs384, Rs512, SecretJwk, VerifyKey,
};

fn go<A: Alg>(key: Result<VerifyKey<A>, Error>, jws: &str) -> Result<(), Error> {
    Jws::parse(jws)?.verify(&key?).map(|_| ())
}

/// Verifies `jws` under the key `jwk` holds for `alg`: an `oct` key for HS, a public key for the rest.
pub(crate) fn verify(alg: &str, jwk: &str, jws: &str) -> Result<(), Error> {
    let (secret, public) = (
        SecretJwk::decode(jwk.as_bytes()),
        Jwk::decode(jwk.as_bytes()),
    );
    match alg {
        "HS256" => go::<Hs256>(secret.and_then(|k| k.verify_key()), jws),
        "HS384" => go::<Hs384>(secret.and_then(|k| k.verify_key()), jws),
        "HS512" => go::<Hs512>(secret.and_then(|k| k.verify_key()), jws),
        "RS256" => go::<Rs256>(public.and_then(|k| k.verify_key()), jws),
        "RS384" => go::<Rs384>(public.and_then(|k| k.verify_key()), jws),
        "RS512" => go::<Rs512>(public.and_then(|k| k.verify_key()), jws),
        "PS256" => go::<Ps256>(public.and_then(|k| k.verify_key()), jws),
        "PS384" => go::<Ps384>(public.and_then(|k| k.verify_key()), jws),
        "PS512" => go::<Ps512>(public.and_then(|k| k.verify_key()), jws),
        "ES256" => go::<Es256>(public.and_then(|k| k.verify_key()), jws),
        "ES384" => go::<Es384>(public.and_then(|k| k.verify_key()), jws),
        "EdDSA" => go::<EdDsa>(public.and_then(|k| k.verify_key()), jws),
        _ => go::<Hs256>(Err(jose::ErrorKind::UnsupportedAlg.into()), jws),
    }
}
