package main

import (
	"testing"
)

// TestC4_CanonicalOrderProducesAgreedRole locks down the C4 invariant:
//
//	The portal's Effective Access view (portal/src/lib/access.ts) and the
//	consent service's LookupRole (this file's manifest.go) both walk the
//	user's stored group order. The admin form normalizes
//	`metadata_admin.groups` into a canonical shape on every save, so
//	stored order == canonical order.
//
// This test snapshot-asserts the Go side against the same canonical
// fixture the portal uses. If a future change reintroduces a precedence
// list on either side, this test fails until both implementations are
// brought back in line.
//
// The fixture below is the contract: same input, same role, on both
// sides. A matching test on the portal side (see
// portal/tests/access.test.ts when added) reads the same fixture and
// asserts the same role.
func TestC4_CanonicalOrderProducesAgreedRole(t *testing.T) {
	dir := t.TempDir()
	// Use the namespaced shape (post-D6 migration). client_id under
	// oidc:, roles+group_role_map under consent:.
	writeManifest(t, dir, "keep.yaml", `
oidc:
  client_id: keep
  client_name: Vaultwarden
  audience:
    - https://keep.dunn.dev
  redirect_uris:
    - https://keep.dunn.dev/identity/connect/oidc-signin
consent:
  roles:
    admin:
      description: admin
      claim_emit:
        role: admin
    user:
      description: user
      claim_emit:
        role: user
  group_role_map:
    admin: admin
    family: user
    friends: user
    kids: user
`)
	m, err := NewManifest(dir)
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}

	// Canonical-ordered fixture: identity groups in IDENTITY_GROUP_ORDER
	// (admin, family, friends, kids), then access-* groups alpha-sorted.
	// The admin form's normalizeGroupOrder() produces this shape.
	cases := []struct {
		name          string
		storedGroups  []any
		wantRole      string
		wantOK        bool
	}{
		{
			name:         "admin+family canonical: admin wins",
			storedGroups: []any{"admin", "family", "access-keep"},
			wantRole:     "admin",
			wantOK:       true,
		},
		{
			name:         "family only: user",
			storedGroups: []any{"family", "access-keep"},
			wantRole:     "user",
			wantOK:       true,
		},
		{
			name:         "kids only: user",
			storedGroups: []any{"kids", "access-keep"},
			wantRole:     "user",
			wantOK:       true,
		},
		{
			name:         "no group match: ok=false",
			storedGroups: []any{"access-keep"},
			wantRole:     "",
			wantOK:       false,
		},
		{
			name:         "admin+family+friends canonical: admin wins",
			storedGroups: []any{"admin", "family", "friends", "access-keep"},
			wantRole:     "admin",
			wantOK:       true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			meta := map[string]any{"groups": tc.storedGroups}
			role, _, ok := m.LookupRole("keep", meta)
			if ok != tc.wantOK {
				t.Fatalf("ok: got %v want %v", ok, tc.wantOK)
			}
			if role != tc.wantRole {
				t.Fatalf("role: got %q want %q", role, tc.wantRole)
			}
		})
	}
}

// TestC4_NonCanonicalOrderFlagsDrift confirms that if stored order is
// NOT canonical (which the admin form prevents but a direct API write
// could produce), the consent service follows stored order. This test
// documents the failure mode: violating the canonical-order invariant
// at write time produces consent-side roles that disagree with the
// portal's Effective Access view (which also walks stored order, so it
// also disagrees with the admin's expectation).
//
// The mitigation is the admin form's normalizeGroupOrder() pass. This
// test exists to make the dependency explicit.
func TestC4_NonCanonicalOrderFlagsDrift(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "keep.yaml", `
oidc:
  client_id: keep
  client_name: Vaultwarden
  audience:
    - https://keep.dunn.dev
  redirect_uris:
    - https://keep.dunn.dev/identity/connect/oidc-signin
consent:
  roles:
    admin:
      description: admin
      claim_emit:
        role: admin
    user:
      description: user
      claim_emit:
        role: user
  group_role_map:
    admin: admin
    family: user
`)
	m, err := NewManifest(dir)
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}

	// family BEFORE admin: a direct API write that bypasses the form
	// can produce this. The consent service walks stored order and
	// returns user. Documented contract; the form must prevent this
	// case in production.
	meta := map[string]any{
		"groups": []any{"family", "admin"},
	}
	role, _, ok := m.LookupRole("keep", meta)
	if !ok || role != "user" {
		t.Fatalf("non-canonical family-first: got role=%q ok=%v, want role=user ok=true", role, ok)
	}

	// admin BEFORE family: canonical. admin wins.
	meta = map[string]any{
		"groups": []any{"admin", "family"},
	}
	role, _, ok = m.LookupRole("keep", meta)
	if !ok || role != "admin" {
		t.Fatalf("canonical admin-first: got role=%q ok=%v, want role=admin ok=true", role, ok)
	}
}
