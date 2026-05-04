package main

import (
	"encoding/json"
	"testing"
)

// FuzzJwkToSigningKey exercises jwkToSigningKey against arbitrary JWK
// JSON. Invariants:
//
//   - The function never panics on any input.
//   - On success, the returned signingKey carries a non-empty alg from
//     the supported set.
//
// Seeded with a couple of valid-shaped JWKs so the fuzzer has
// somewhere to mutate from.
func FuzzJwkToSigningKey(f *testing.F) {
	// Seed: minimal RSA private JWK shape (values not real keys; the
	// fuzzer mutates them).
	f.Add([]byte(`{"kty":"RSA","alg":"RS256","kid":"k1","use":"sig","n":"AQAB","e":"AQAB","d":"AQAB","p":"AQAB","q":"AQAB","dp":"AQAB","dq":"AQAB","qi":"AQAB"}`))
	f.Add([]byte(`{"kty":"EC","alg":"ES256","kid":"e1","use":"sig","crv":"P-256","x":"AQAB","y":"AQAB","d":"AQAB"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"kty":"oct","k":"AQAB"}`))
	f.Add([]byte(`null`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		var jwk hydraJWK
		if err := json.Unmarshal(raw, &jwk); err != nil {
			// Unmarshal errors are expected; not a panic, fuzzer can't
			// reach the function under test.
			return
		}

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("jwkToSigningKey panicked on input %q: %v", string(raw), r)
			}
		}()

		key, err := jwkToSigningKey(jwk)
		if err != nil {
			// Errors are fine; the invariant is "no panic."
			return
		}
		// Successful key construction must carry a known alg.
		switch key.alg {
		case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512":
			// ok
		default:
			t.Fatalf("jwkToSigningKey returned unknown alg %q on input %q", key.alg, string(raw))
		}
	})
}
