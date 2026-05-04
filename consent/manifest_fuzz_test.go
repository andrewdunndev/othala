package main

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzLoadClientManifest exercises loadClientManifest with arbitrary
// YAML bytes. Invariants:
//
//   - The function never panics on any input.
//   - When the parse succeeds, declared roles either have a non-nil
//     ClaimEmit map or none at all (empty map is fine; nil is the
//     "missing" signal that ValidateManifests flags).
//
// Seeded with valid manifest shapes from manifest_test.go.
func FuzzLoadClientManifest(f *testing.F) {
	f.Add([]byte(`oidc:
  client_id: keep
  audience:
    - https://keep.dunn.dev
  redirect_uris:
    - https://keep.dunn.dev/cb
consent:
  roles:
    user:
      description: ok
      claim_emit:
        role: user
  group_role_map:
    family: user
`))
	f.Add([]byte(`oidc: {}
consent: {}
`))
	f.Add([]byte(`---
client_id: legacy
roles: {}
`))
	f.Add([]byte(``))
	f.Add([]byte(`<<<not yaml>>>`))

	f.Fuzz(func(t *testing.T, body []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "fuzz.yaml")
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatalf("write tempfile: %v", err)
		}

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("loadClientManifest panicked on body %q: %v", string(body), r)
			}
		}()

		cm, err := loadClientManifest(path)
		if err != nil {
			return
		}
		if cm == nil {
			t.Fatalf("loadClientManifest returned (nil, nil) on body %q", string(body))
		}
		// Invariant: if any roles are declared, the resulting map is
		// addressable and we can iterate without panicking. The
		// validator ValidateManifests flags missing claim_emit; the
		// loader does not enforce that.
		for name, role := range cm.Consent.Roles {
			if name == "" {
				t.Fatalf("loadClientManifest returned empty role name on body %q", string(body))
			}
			// role.ClaimEmit may be nil; that's a valid post-load state
			// (the validator catches it). Just confirm we can read.
			_ = role.ClaimEmit
		}
	})
}
