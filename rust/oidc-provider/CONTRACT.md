# oidc-provider contract

The public surface is the generated `public-api.txt`. This is the first slice of the provider: the issuer, the one discovery document, the JWKS, routing, error responses, bounds and redacting `Debug`. The authorization endpoint and the token endpoint are advertised and routed here and answered by later items (N1, N2). Each claim carries one tag: *Type* (the program does not compile, or the snapshot lacks the item), *Runtime* (a check returns an error or a value), *Obligation* (the host's, which the crate cannot see). Non-goals follow; each names the claim that holds it.

Checks:
- `api:<Item>` is an item path the committed `public-api.txt` declares (`Type::method`, or a bare top-level name) and `api-absent:<Item>` one it does not declare (a bare name matches no path's last segment); the snapshot is `just api`.
- `row:x` is `tests/row_x.rs`, one file per family, holding a `#[test]`.
- `mutants:m` is `src/m.rs`, whose functions `just mutants oidc-provider` mutates with none missed.
- `gate:x` is `just x` with this crate's `gates.json`.

## Type
- T1 The discovery document and the JWKS come only from the `Provider` that routes: the document is built inside `Provider::new` and no accessor takes bytes in: api-absent:Provider::with_metadata, api:Provider::metadata_json, api:Provider::jwks.
- T2 The JWKS holds public keys only, because `SigningKeys::new` takes `jose::Jwk`, which cannot hold private members, and `jose::JwkSet` writes only those: api:SigningKeys::new, api-absent:SecretJwk.
- T3 `Lifetimes` is built only through its builder, so no lifetime has a default: api:Lifetimes::builder, api-absent:Lifetimes::new, api:LifetimesBuilder::build.
- T4 Every public enum is `#[non_exhaustive]`: `just api`.
- T5 The crate holds no clock, entropy, store or socket, and its dependencies are `deps.txt`'s (jose, http, serde, serde_json): api-absent:Store, api-absent:Effect, gate:lint, gate:deps.
- T6 It builds for wasm32-unknown-unknown and on the MSRV against the committed lock: gate:wasm, gate:msrv.

## Runtime: issuer and keys
- R1 `IssuerUrl::parse` accepts an `https` URL with a lowercase DNS host, an optional port 1 to 65535, and an optional path of unreserved segments, up to `MAX_ISSUER` bytes; it refuses another scheme, a query, a fragment, userinfo, an IP literal, percent-encoding, an empty, dot or dot-dot segment and a trailing slash as `Malformed`, and a longer text as `TooLarge`; the text is kept as given (OpenID Connect Core 2, Discovery 3): row:issuer, mutants:issuer.
- R2 `SigningKeys::new` accepts a key only with a `kid` (`Missing`), `alg` `RS256`, `use` `sig` and an RSA key (`Malformed`); a modulus under 2048 bits is refused by jose when the JWK is decoded (RFC 7518 3.3, OpenID Connect Core 15.1): row:keys, mutants:keys.
- R3 `SigningKeys::new` keeps the given order of any number of keys from one to `MAX_KEYS`, so a new key can be published before it signs; none is `Missing`, more is `TooLarge` and a `kid` given twice is `Duplicate`: row:keys, mutants:keys.

## Runtime: discovery and routing
- R4 The discovery document is exactly the bytes the row writes, for a root issuer and for one with a port and path: the endpoints are under the issuer, `response_types_supported` is `["code"]`, `response_modes_supported` `["query"]`, `grant_types_supported` `["authorization_code"]`, `subject_types_supported` `["public"]`, `id_token_signing_alg_values_supported` `["RS256"]`, `token_endpoint_auth_methods_supported` `["client_secret_basic","none"]`, `code_challenge_methods_supported` `["S256"]`; nothing outside the first slice is advertised (Discovery 3, RFC 9700 2.1.1): row:metadata, mutants:metadata.
- R5 Each member whose Discovery default claims more than this provider does is written out: `response_modes_supported`, `grant_types_supported`, `token_endpoint_auth_methods_supported` and `request_uri_parameter_supported` (Discovery 3), with `request_parameter_supported` and `claims_parameter_supported` false: row:metadata.
- R6 `authorization_response_iss_parameter_supported` is true, which the authorization endpoint's `iss` parameter (RFC 9207 3) will honour: row:metadata.
- R7 Every advertised endpoint routes: the authorization endpoint for `GET` and `POST` (Core 3.1.2.1), the token endpoint for `POST` (RFC 6749 3.2), the JWKS and the well-known document (Discovery 4, appended to the issuer) for `GET`, each under the issuer's path: row:metadata, row:routing, mutants:provider.
- R8 The JWKS served at `jwks_uri` lists each key's public members with `kid`, `alg` `RS256` and `use` `sig`, in order, as `application/json`, and no private member: row:metadata, mutants:provider.
- R9 `route` answers `NotFound` for another method on a known path, another path, a trailing slash or a case change; a target past `MAX_TARGET` is `TargetTooLong` before a body past `MAX_BODY` is `BodyTooLarge`, each inclusive at its bound: row:routing, mutants:provider.
- R10 `respond` answers the document and the JWKS, and 404, 414 and 413 with no body and no header; `Authorize` and `Token` give none, since later items answer them: row:routing.

## Runtime: errors, lifetimes, Debug
- R11 Each `ErrorCode` has its registered name, one status (401 for `invalid_client`, 500 for `server_error`, else 400) and the body `{"error":"<name>"}`, and its response is `application/json` with `Cache-Control: no-store` and `Pragma: no-cache` (RFC 6749 5.1, 5.2): row:errors, mutants:error.
- R12 `LifetimesBuilder::build` refuses an unset lifetime as `Missing`, zero as `Malformed` and a lifetime past its bound as `TooLarge`, each bound inclusive: the code at `MAX_CODE_SECS` (RFC 6749 4.1.2), the access and ID token at `MAX_TOKEN_SECS`, the ticket at `MAX_TICKET_SECS`: row:limits, mutants:lifetimes.
- R13 The `Debug` of a `Provider` is its issuer, its kids and its lifetimes, and no key member: row:redaction.

## Obligation
- O1 The host serves every route over TLS and answers only for the issuer's host (Discovery 4.2; RFC 6749 3.1): the host's.
- O2 The host buffers at most `MAX_BODY` bytes of a request before it calls `route`: the host's.
- O3 A key's private half stays in host secrets, and a key signs only once its `kid` has been published for as long as clients cache the JWKS: the host's.

## Non-goal
- N1 The authorization endpoint (parameters, `redirect_uri` matching, PKCE, tickets, the `iss` parameter): the next item; `Route::Authorize` has no answer here (R10).
- N2 The token endpoint, client authentication, codes and the ID token, so also signing, the `rsa-sign` feature and a `WWW-Authenticate` challenge on a 401: the item after; R11 gives the status and body only.
- N3 Refresh tokens, so `refresh_token` is not an advertised grant (R4).
- N4 Userinfo, revocation, introspection, registration, logout, `request` and `request_uri` objects, implicit and hybrid flows, other signing algorithms: R4 advertises none of them.
- N5 A `405` with `Allow` for a wrong method: R9 answers `NotFound`.
- N6 The RFC 8414 well-known path: an OpenID provider needs only the one in R7.
