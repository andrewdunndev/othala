package main

import (
	"reflect"
	"testing"
)

func TestBuildIDTokenClaims_Full(t *testing.T) {
	id := &Identity{
		ID: "01J0...",
		Traits: map[string]any{
			"username":    "andrew.dunn",
			"email":       "andrew@example.com",
			"displayName": "Andrew Dunn",
		},
		VerifiableAddresses: []VerifiableAddress{
			{Value: "andrew@example.com", Verified: true, Via: "email"},
		},
		MetadataAdmin: map[string]any{
			"groups": []any{"admin", "family", "access-keep"},
		},
	}

	claims := BuildIDTokenClaims(id)

	want := map[string]any{
		"email":              "andrew@example.com",
		"email_verified":     true,
		"name":               "Andrew Dunn",
		"preferred_username": "andrew.dunn",
		"groups":             []string{"admin", "family", "access-keep"},
	}
	if !reflect.DeepEqual(claims, want) {
		t.Fatalf("claims mismatch\nwant: %#v\ngot:  %#v", want, claims)
	}
}

func TestBuildIDTokenClaims_NoDisplayNameFallsBackToUsername(t *testing.T) {
	id := &Identity{
		Traits: map[string]any{
			"username": "kid.one",
			"email":    "kid@example.com",
		},
		VerifiableAddresses: []VerifiableAddress{
			{Value: "kid@example.com", Verified: false, Via: "email"},
		},
	}

	claims := BuildIDTokenClaims(id)

	if claims["name"] != "kid.one" {
		t.Fatalf("name fallback wrong: %v", claims["name"])
	}
	if claims["email_verified"] != false {
		t.Fatalf("email_verified should be false: %v", claims["email_verified"])
	}
	if _, ok := claims["groups"]; ok {
		t.Fatalf("groups should be omitted when metadata_admin missing")
	}
}

func TestBuildIDTokenClaims_NoVerifiableAddressesOmitsClaim(t *testing.T) {
	id := &Identity{
		Traits: map[string]any{
			"username": "x.y",
			"email":    "xy@example.com",
		},
	}

	claims := BuildIDTokenClaims(id)
	if _, ok := claims["email_verified"]; ok {
		t.Fatal("email_verified should be omitted with no addresses")
	}
}

func TestBuildIDTokenClaims_GroupsAsStringSlice(t *testing.T) {
	id := &Identity{
		Traits: map[string]any{"username": "u", "email": "u@e.com"},
		MetadataAdmin: map[string]any{
			"groups": []string{"a", "b"},
		},
	}
	claims := BuildIDTokenClaims(id)
	got, ok := claims["groups"].([]string)
	if !ok || !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("groups []string passthrough failed: %v", claims["groups"])
	}
}

func TestBuildIDTokenClaims_GroupsDropsNonStrings(t *testing.T) {
	id := &Identity{
		Traits: map[string]any{"username": "u", "email": "u@e.com"},
		MetadataAdmin: map[string]any{
			"groups": []any{"admin", 42, "family"},
		},
	}
	claims := BuildIDTokenClaims(id)
	got := claims["groups"].([]string)
	if !reflect.DeepEqual(got, []string{"admin", "family"}) {
		t.Fatalf("non-string group not dropped: %v", got)
	}
}

func TestBuildIDTokenClaims_NilIdentitySafe(t *testing.T) {
	claims := BuildIDTokenClaims(nil)
	if len(claims) != 0 {
		t.Fatalf("nil identity should produce empty claims, got %v", claims)
	}
}

func TestBuildIDTokenClaims_EmailMatchedAcrossMultipleAddresses(t *testing.T) {
	id := &Identity{
		Traits: map[string]any{"username": "u", "email": "primary@e.com"},
		VerifiableAddresses: []VerifiableAddress{
			{Value: "old@e.com", Verified: true, Via: "email"},
			{Value: "primary@e.com", Verified: false, Via: "email"},
		},
	}
	claims := BuildIDTokenClaims(id)
	if claims["email_verified"] != false {
		t.Fatalf("expected verified=false for primary email, got %v", claims["email_verified"])
	}
}

// TestDeepMergeNestedClaimEmit covers the Vaultwarden-mainline (future)
// shape: a role's claim_emit injects a nested resource_access path
// alongside an existing top-level claim. The base claims (email, sub)
// and the existing top-level groups must coexist with the nested map.
func TestDeepMergeNestedClaimEmit(t *testing.T) {
	dst := map[string]any{
		"email":              "andrew@example.com",
		"sub":                "01J0",
		"preferred_username": "andrew.dunn",
		"groups":             []string{"family"},
	}
	src := map[string]any{
		"resource_access": map[string]any{
			"keep": map[string]any{
				"roles": []any{"admin"},
			},
		},
		"groups": []any{"admin"},
	}
	deepMergeClaims(dst, src)

	if dst["email"] != "andrew@example.com" {
		t.Fatalf("email lost: %v", dst["email"])
	}
	if dst["sub"] != "01J0" {
		t.Fatalf("sub lost: %v", dst["sub"])
	}
	if dst["preferred_username"] != "andrew.dunn" {
		t.Fatalf("preferred_username lost: %v", dst["preferred_username"])
	}
	// groups is last-write-wins; src overrides.
	got, ok := dst["groups"].([]any)
	if !ok || !reflect.DeepEqual(got, []any{"admin"}) {
		t.Fatalf("groups override failed: %#v", dst["groups"])
	}
	ra, ok := dst["resource_access"].(map[string]any)
	if !ok {
		t.Fatalf("resource_access missing or wrong type: %#v", dst["resource_access"])
	}
	keep, ok := ra["keep"].(map[string]any)
	if !ok {
		t.Fatalf("resource_access.keep missing: %#v", ra)
	}
	roles, ok := keep["roles"].([]any)
	if !ok || !reflect.DeepEqual(roles, []any{"admin"}) {
		t.Fatalf("nested roles lost: %#v", keep["roles"])
	}
}

// TestDeepMergeMultipleNestedKeys covers the Grafana shape: grafana_role,
// groups, plus the standard email/sub coexist after merge. All scalars
// land at the top level, no nesting collapses.
func TestDeepMergeMultipleNestedKeys(t *testing.T) {
	dst := map[string]any{
		"email":  "a@b.com",
		"sub":    "01J0",
		"groups": []string{"family"},
	}
	src := map[string]any{
		"grafana_role": []any{"GrafanaAdmin"},
		"groups":       []any{"admin"},
	}
	deepMergeClaims(dst, src)

	if dst["email"] != "a@b.com" || dst["sub"] != "01J0" {
		t.Fatalf("base claims dropped: %+v", dst)
	}
	gr, ok := dst["grafana_role"].([]any)
	if !ok || !reflect.DeepEqual(gr, []any{"GrafanaAdmin"}) {
		t.Fatalf("grafana_role wrong: %#v", dst["grafana_role"])
	}
	g, ok := dst["groups"].([]any)
	if !ok || !reflect.DeepEqual(g, []any{"admin"}) {
		t.Fatalf("groups not overridden: %#v", dst["groups"])
	}
}

// TestDeepMergeArrayConcat documents and locks the chosen behavior:
// overlapping array claims are last-write-wins, NOT array-union. This
// matches existing v2 behavior where a role's claim_emit.groups
// overrides the auto groups claim sourced from identity.metadata_admin.
func TestDeepMergeArrayConcat(t *testing.T) {
	dst := map[string]any{
		"groups": []string{"family", "kids"},
	}
	src := map[string]any{
		"groups": []any{"admin"},
	}
	deepMergeClaims(dst, src)

	got, ok := dst["groups"].([]any)
	if !ok {
		t.Fatalf("expected []any after override, got %T: %v", dst["groups"], dst["groups"])
	}
	if !reflect.DeepEqual(got, []any{"admin"}) {
		t.Fatalf("expected last-write-wins [admin], got %#v", got)
	}
}

func TestDeepMergeClaims_NilSrcIsNoop(t *testing.T) {
	dst := map[string]any{"email": "a@b.com"}
	deepMergeClaims(dst, nil)
	if !reflect.DeepEqual(dst, map[string]any{"email": "a@b.com"}) {
		t.Fatalf("nil src changed dst: %+v", dst)
	}
}

func TestDeepMergeClaims_AddsMissingKeys(t *testing.T) {
	dst := map[string]any{"email": "a@b.com"}
	src := map[string]any{"vw_admin": true, "role": "admin"}
	deepMergeClaims(dst, src)
	if dst["vw_admin"] != true || dst["role"] != "admin" {
		t.Fatalf("missing keys not added: %+v", dst)
	}
}

func TestDeepMergeClaims_NestedMapMergesRecursively(t *testing.T) {
	dst := map[string]any{
		"resource_access": map[string]any{
			"other_client": map[string]any{"roles": []any{"viewer"}},
		},
	}
	src := map[string]any{
		"resource_access": map[string]any{
			"keep": map[string]any{"roles": []any{"admin"}},
		},
	}
	deepMergeClaims(dst, src)

	ra := dst["resource_access"].(map[string]any)
	if _, ok := ra["other_client"]; !ok {
		t.Fatalf("nested merge dropped sibling key: %+v", ra)
	}
	if _, ok := ra["keep"]; !ok {
		t.Fatalf("nested merge missed new key: %+v", ra)
	}
}

// TestDeepMergeClaims_RoleClaimEmitOverridesAutoGroups locks the answer
// to the question "what if a role's claim_emit groups conflicts with the
// auto groups claim?" Role wins. This matches what keep.yaml relies on:
// admin role's claim_emit.groups = ["admin"] replaces the user's
// identity groups = ["family", "access-keep"] in the id_token sent to
// Vaultwarden.
func TestDeepMergeClaims_RoleClaimEmitOverridesAutoGroups(t *testing.T) {
	autoGroups := []string{"family", "access-keep"}
	dst := map[string]any{"groups": autoGroups}
	src := map[string]any{"groups": []any{"admin"}}
	deepMergeClaims(dst, src)
	got := dst["groups"]
	if !reflect.DeepEqual(got, []any{"admin"}) {
		t.Fatalf("role's claim_emit.groups should override auto groups, got %#v", got)
	}
}

// TestEmitGroupsClaimFalseSuppressesGroups verifies the tailscale-shape
// flow: BuildIDTokenClaims emits the auto groups claim, the manifest
// then suppresses it because emit_groups_claim is false, and the role's
// (empty) claim_emit doesn't put it back.
func TestEmitGroupsClaimFalseSuppressesGroups(t *testing.T) {
	id := &Identity{
		Traits: map[string]any{"username": "u", "email": "u@e.com"},
		MetadataAdmin: map[string]any{
			"groups": []any{"family"},
		},
	}
	claims := BuildIDTokenClaims(id)
	if _, ok := claims["groups"]; !ok {
		t.Fatal("precondition: BuildIDTokenClaims should emit groups when present")
	}

	emit := false
	cm := &ClientManifest{
		OIDC:    OIDCConfig{ClientID: "tailscale"},
		Consent: ConsentConfig{EmitGroupsClaim: &emit},
	}
	if cm.ShouldEmitGroups() {
		t.Fatal("ShouldEmitGroups must be false")
	}
	// Suppression simulation matches handlers.go: when ShouldEmitGroups
	// returns false, the auto groups claim is dropped before the role
	// merge runs.
	delete(claims, "groups")
	// Empty claim_emit, as tailscale.yaml uses.
	deepMergeClaims(claims, map[string]any{})

	if _, ok := claims["groups"]; ok {
		t.Fatalf("groups should be suppressed: %+v", claims)
	}
	if claims["email"] != "u@e.com" {
		t.Fatalf("non-groups claims should be intact: %+v", claims)
	}
}

// TestEmitGroupsClaimDefaultEmits verifies the default case: a manifest
// without emit_groups_claim leaves the auto groups claim intact and
// the role's claim_emit merges over it.
func TestEmitGroupsClaimDefaultEmits(t *testing.T) {
	id := &Identity{
		Traits: map[string]any{"username": "u", "email": "u@e.com"},
		MetadataAdmin: map[string]any{
			"groups": []any{"family"},
		},
	}
	claims := BuildIDTokenClaims(id)

	cm := &ClientManifest{OIDC: OIDCConfig{ClientID: "larder"}}
	if !cm.ShouldEmitGroups() {
		t.Fatal("default ShouldEmitGroups should be true")
	}
	// No deletion; merge a flat role claim.
	deepMergeClaims(claims, map[string]any{"mealie_role": "user"})

	groups, ok := claims["groups"].([]string)
	if !ok || !reflect.DeepEqual(groups, []string{"family"}) {
		t.Fatalf("groups should be preserved, got %#v", claims["groups"])
	}
	if claims["mealie_role"] != "user" {
		t.Fatalf("role claim not merged: %+v", claims)
	}
}
