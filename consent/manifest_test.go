package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// writeManifest writes one yaml file under dir and returns its path.
func writeManifest(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

const keepYAML = `oidc:
  client_id: keep
  client_name: Vaultwarden
  skip_consent: true
  redirect_uris:
    - https://keep.dunn.dev/identity/connect/oidc-signin
  audience:
    - https://keep.dunn.dev
consent:
  roles:
    admin:
      description: Vaultwarden admin
      claim_emit:
        role: admin
        vw_admin: true
    user:
      description: Vaultwarden user
      claim_emit:
        role: user
  group_role_map:
    admin: admin
    family: user
    kids: user
`

const larderYAML = `oidc:
  client_id: larder
  client_name: Mealie
  skip_consent: true
  redirect_uris:
    - https://larder.dunn.dev/login
  audience:
    - https://larder.dunn.dev
consent:
  roles:
    admin:
      description: Mealie admin
      claim_emit:
        mealie_role: admin
    user:
      description: Mealie user
      claim_emit:
        mealie_role: user
  group_role_map:
    admin: admin
    family: user
`

// legacyYAML has no roles section. Back-compat: LookupRole must report
// ok=false and the consent flow continues to emit groups only.
const legacyYAML = `oidc:
  client_id: cinema
  client_name: Cinema
  skip_consent: true
  redirect_uris:
    - https://cinema.dunn.dev/sso/OID/redirect/dunn
  audience:
    - https://cinema.dunn.dev
consent: {}
`

func newTestManifestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeManifest(t, dir, "keep.yaml", keepYAML)
	writeManifest(t, dir, "larder.yaml", larderYAML)
	writeManifest(t, dir, "cinema.yaml", legacyYAML)
	return dir
}

func TestManifest_Load_ParsesRolesAndGroupRoleMap(t *testing.T) {
	dir := newTestManifestDir(t)
	m, err := NewManifest(dir)
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}

	keep := m.Client("keep")
	if keep == nil {
		t.Fatal("keep manifest missing")
	}
	if keep.OIDC.ClientName != "Vaultwarden" {
		t.Fatalf("client_name: %q", keep.OIDC.ClientName)
	}
	if !keep.OIDC.SkipConsent {
		t.Fatal("skip_consent not parsed")
	}
	if len(keep.Consent.Roles) != 2 {
		t.Fatalf("roles count: %d", len(keep.Consent.Roles))
	}
	admin, ok := keep.Consent.Roles["admin"]
	if !ok {
		t.Fatal("admin role missing")
	}
	if admin.Description != "Vaultwarden admin" {
		t.Fatalf("admin description: %q", admin.Description)
	}
	if admin.ClaimEmit["role"] != "admin" || admin.ClaimEmit["vw_admin"] != true {
		t.Fatalf("admin claim_emit: %+v", admin.ClaimEmit)
	}
	if keep.Consent.GroupRoleMap["family"] != "user" {
		t.Fatalf("group_role_map[family]: %q", keep.Consent.GroupRoleMap["family"])
	}

	cinema := m.Client("cinema")
	if cinema == nil {
		t.Fatal("cinema manifest missing")
	}
	if len(cinema.Consent.Roles) != 0 || len(cinema.Consent.GroupRoleMap) != 0 {
		t.Fatalf("legacy yaml should have empty roles/group_role_map: %+v", cinema)
	}
}

func TestManifest_LookupRole_OverrideWins(t *testing.T) {
	dir := newTestManifestDir(t)
	m, err := NewManifest(dir)
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}

	// metadata_admin.roles.keep = admin overrides group derivation that
	// would otherwise place this user in the user role via family.
	meta := map[string]any{
		"groups": []any{"family"},
		"roles":  map[string]any{"keep": "admin"},
	}

	role, claims, ok := m.LookupRole("keep", meta)
	if !ok {
		t.Fatal("expected ok=true for override")
	}
	if role != "admin" {
		t.Fatalf("override role: %q", role)
	}
	want := map[string]any{"role": "admin", "vw_admin": true}
	if !reflect.DeepEqual(claims, want) {
		t.Fatalf("claims:\nwant %+v\ngot  %+v", want, claims)
	}
}

func TestManifest_LookupRole_DerivesFromGroupsFirstMatch(t *testing.T) {
	dir := newTestManifestDir(t)
	m, err := NewManifest(dir)
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}

	// First group "access-keep" does not appear in keep.group_role_map.
	// Second group "family" maps to user. user must win, not admin (which
	// would be wrong; this user is not in the admin group).
	meta := map[string]any{
		"groups": []any{"access-keep", "family", "kids"},
	}
	role, claims, ok := m.LookupRole("keep", meta)
	if !ok {
		t.Fatal("expected ok=true for derive")
	}
	if role != "user" {
		t.Fatalf("derived role: %q", role)
	}
	if claims["role"] != "user" {
		t.Fatalf("derived claims: %+v", claims)
	}
}

func TestManifest_LookupRole_AdminGroupBeatsFamilyWhenFirst(t *testing.T) {
	dir := newTestManifestDir(t)
	m, err := NewManifest(dir)
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}

	// Order matters: admin first, family second. Admin wins.
	meta := map[string]any{
		"groups": []any{"admin", "family"},
	}
	role, _, ok := m.LookupRole("keep", meta)
	if !ok || role != "admin" {
		t.Fatalf("admin-first: ok=%v role=%q", ok, role)
	}

	// Reversed: family first. family maps to user; user wins.
	meta = map[string]any{
		"groups": []any{"family", "admin"},
	}
	role, _, ok = m.LookupRole("keep", meta)
	if !ok || role != "user" {
		t.Fatalf("family-first: ok=%v role=%q", ok, role)
	}
}

func TestManifest_LookupRole_NoMatchReturnsFalse(t *testing.T) {
	dir := newTestManifestDir(t)
	m, err := NewManifest(dir)
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}

	// No override, no groups that match the manifest's group_role_map.
	meta := map[string]any{
		"groups": []any{"unrelated-group", "another"},
	}
	if _, _, ok := m.LookupRole("keep", meta); ok {
		t.Fatal("expected ok=false when no group matches")
	}

	// No metadata at all.
	if _, _, ok := m.LookupRole("keep", nil); ok {
		t.Fatal("expected ok=false on nil metadata")
	}

	// Override names a role that doesn't exist; with no group fallback, ok=false.
	meta = map[string]any{
		"roles":  map[string]any{"keep": "nonexistent"},
		"groups": []any{"unrelated"},
	}
	if _, _, ok := m.LookupRole("keep", meta); ok {
		t.Fatal("expected ok=false when override role is undeclared and no group falls back")
	}
}

func TestManifest_LookupRole_BadOverrideFallsBackToGroups(t *testing.T) {
	dir := newTestManifestDir(t)
	m, err := NewManifest(dir)
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}

	// Override names a role that's not declared in keep.yaml. Resolution
	// should fall through to group derivation rather than emit nothing,
	// so a typo doesn't strip a user of access.
	meta := map[string]any{
		"groups": []any{"family"},
		"roles":  map[string]any{"keep": "ghost"},
	}
	role, _, ok := m.LookupRole("keep", meta)
	if !ok || role != "user" {
		t.Fatalf("bad-override fallback: ok=%v role=%q", ok, role)
	}
}

func TestManifest_LookupRole_NoRolesSectionMeansSkip(t *testing.T) {
	dir := newTestManifestDir(t)
	m, err := NewManifest(dir)
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}

	// cinema has no roles declared. Always ok=false; consent handler
	// emits groups only.
	meta := map[string]any{
		"groups": []any{"family", "admin"},
		"roles":  map[string]any{"cinema": "admin"},
	}
	if _, _, ok := m.LookupRole("cinema", meta); ok {
		t.Fatal("expected ok=false for client with no roles declared")
	}
}

func TestManifest_LookupRole_UnknownClientReturnsFalse(t *testing.T) {
	dir := newTestManifestDir(t)
	m, err := NewManifest(dir)
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}
	if _, _, ok := m.LookupRole("nonexistent", map[string]any{"groups": []any{"family"}}); ok {
		t.Fatal("expected ok=false for unknown client")
	}
}

func TestManifest_LookupRole_GroupsAsStringSlice(t *testing.T) {
	dir := newTestManifestDir(t)
	m, err := NewManifest(dir)
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}
	// Some callers may hand us []string directly (e.g., synthetic data
	// in tests). The resolver must tolerate it.
	meta := map[string]any{
		"groups": []string{"family"},
	}
	role, _, ok := m.LookupRole("keep", meta)
	if !ok || role != "user" {
		t.Fatalf("string slice path: ok=%v role=%q", ok, role)
	}
}

func TestManifest_Reload_ReplacesState(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "keep.yaml", keepYAML)
	m, err := NewManifest(dir)
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}
	if m.Client("keep") == nil {
		t.Fatal("keep missing on initial load")
	}
	if m.Client("larder") != nil {
		t.Fatal("larder unexpectedly present")
	}

	// Add a new manifest, reload, expect it to appear.
	writeManifest(t, dir, "larder.yaml", larderYAML)
	if err := m.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if m.Client("larder") == nil {
		t.Fatal("larder missing after reload")
	}
}

func TestManifest_Reload_BadYAMLLeavesPreviousStateAlone(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "keep.yaml", keepYAML)
	m, err := NewManifest(dir)
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}

	writeManifest(t, dir, "broken.yaml", "oidc:\n  client_id: broken\nconsent:\n  roles:\n    admin: this-is-not-a-role-object\n")
	if err := m.Reload(); err == nil {
		t.Fatal("expected reload to fail on malformed yaml")
	}
	// Previous state must remain intact.
	if m.Client("keep") == nil {
		t.Fatal("keep dropped after failed reload")
	}
}

func TestManifest_DuplicateClientID(t *testing.T) {
	dir := t.TempDir()
	body := `oidc:
  client_id: dup
  redirect_uris: [https://dup.dunn.dev/cb]
  audience: [https://dup.dunn.dev]
consent: {}
`
	writeManifest(t, dir, "a.yaml", body)
	writeManifest(t, dir, "b.yaml", body)
	if _, err := NewManifest(dir); err == nil {
		t.Fatal("expected error on duplicate client_id")
	}
}

func TestManifest_RejectsLegacyFlatShape(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "legacy.yaml", `client_id: legacy
client_name: Legacy
audience:
  - https://legacy.dunn.dev
redirect_uris:
  - https://legacy.dunn.dev/cb
roles:
  admin:
    description: ok
    claim_emit:
      role: admin
group_role_map:
  admin: admin
`)
	_, err := NewManifest(dir)
	if err == nil {
		t.Fatal("expected loader to reject pre-namespace flat shape")
	}
	if !containsString(err.Error(), "pre-namespace flat shape") {
		t.Fatalf("expected legacy-shape error, got %v", err)
	}
}

func TestManifest_ValidateManifests_FlagsBadGroupRoleMap(t *testing.T) {
	// M2: Reload validates before swap, so a manifest with an undeclared
	// role in group_role_map causes NewManifest itself to fail. The error
	// surfaces the lint finding so an operator can fix it without grepping
	// logs.
	dir := t.TempDir()
	writeManifest(t, dir, "bad.yaml", `oidc:
  client_id: bad
  redirect_uris:
    - https://bad.dunn.dev/cb
  audience:
    - https://bad.dunn.dev
consent:
  roles:
    admin:
      description: ok
      claim_emit:
        role: admin
  group_role_map:
    family: user
`)
	if _, err := NewManifest(dir); err == nil {
		t.Fatal("expected NewManifest to fail with bad group_role_map")
	}
}

func TestManifest_ValidateManifests_CleanReturnsEmpty(t *testing.T) {
	dir := newTestManifestDir(t)
	m, err := NewManifest(dir)
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}
	if errs := m.ValidateManifests(); len(errs) != 0 {
		t.Fatalf("expected clean, got %v", errs)
	}
}

func TestManifest_ValidateManifests_MissingAudience(t *testing.T) {
	// H4: every client must have an audience. Reload (M2) fails when this
	// invariant is broken, so NewManifest surfaces the error directly.
	dir := t.TempDir()
	writeManifest(t, dir, "noaud.yaml", `oidc:
  client_id: noaud
  client_name: NoAud
  redirect_uris:
    - https://noaud.dunn.dev/cb
consent: {}
`)
	_, err := NewManifest(dir)
	if err == nil {
		t.Fatal("expected NewManifest to fail when audience missing")
	}
	if !containsString(err.Error(), "oidc.audience is empty") {
		t.Fatalf("expected 'oidc.audience is empty' error, got %v", err)
	}
}

func TestManifest_ValidateManifests_AudienceHostMismatch(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "mismatch.yaml", `oidc:
  client_id: mismatch
  client_name: Mismatch
  redirect_uris:
    - https://app.dunn.dev/cb
  audience:
    - https://elsewhere.dunn.dev
consent: {}
`)
	if _, err := NewManifest(dir); err == nil {
		t.Fatal("expected NewManifest to fail with audience/redirect host mismatch")
	}
}

func TestManifest_ValidateManifests_EmitGroupsFalseWithRoleGroups(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "contradict.yaml", `oidc:
  client_id: contradict
  redirect_uris:
    - https://contradict.dunn.dev/cb
  audience:
    - https://contradict.dunn.dev
consent:
  emit_groups_claim: false
  roles:
    user:
      description: u
      claim_emit:
        groups: ["x"]
  group_role_map:
    family: user
`)
	if _, err := NewManifest(dir); err == nil {
		t.Fatal("expected NewManifest to fail with emit_groups_claim:false + role groups contradiction")
	}
}

const tailscaleYAML = `oidc:
  client_id: tailscale
  client_name: Tailscale
  skip_consent: true
  redirect_uris:
    - https://login.tailscale.com/a/oauth_response
  audience:
    - https://login.tailscale.com
consent:
  roles:
    user:
      description: identity-only
      claim_emit: {}
  group_role_map:
    family: user
  emit_groups_claim: false
`

func TestManifest_ShouldEmitGroups_DefaultTrue(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "keep.yaml", keepYAML)
	m, err := NewManifest(dir)
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}
	keep := m.Client("keep")
	if keep == nil {
		t.Fatal("keep missing")
	}
	if keep.Consent.EmitGroupsClaim != nil {
		t.Fatalf("EmitGroupsClaim should be nil when key absent, got %v", *keep.Consent.EmitGroupsClaim)
	}
	if !keep.ShouldEmitGroups() {
		t.Fatal("default ShouldEmitGroups should be true")
	}
}

func TestManifest_ShouldEmitGroups_ExplicitFalseSuppresses(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "tailscale.yaml", tailscaleYAML)
	m, err := NewManifest(dir)
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}
	ts := m.Client("tailscale")
	if ts == nil {
		t.Fatal("tailscale missing")
	}
	if ts.Consent.EmitGroupsClaim == nil {
		t.Fatal("EmitGroupsClaim should be parsed when set")
	}
	if *ts.Consent.EmitGroupsClaim != false {
		t.Fatalf("EmitGroupsClaim parsed wrong: %v", *ts.Consent.EmitGroupsClaim)
	}
	if ts.ShouldEmitGroups() {
		t.Fatal("ShouldEmitGroups should be false when emit_groups_claim: false")
	}
}

func TestManifest_ShouldEmitGroups_NilReceiverSafe(t *testing.T) {
	var cm *ClientManifest
	if !cm.ShouldEmitGroups() {
		t.Fatal("nil receiver should default to true")
	}
}

func TestManifest_ShouldEmitGroups_ExplicitTrue(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "explicit.yaml", `oidc:
  client_id: explicit
  redirect_uris:
    - https://explicit.dunn.dev/cb
  audience:
    - https://explicit.dunn.dev
consent:
  emit_groups_claim: true
`)
	m, err := NewManifest(dir)
	if err != nil {
		t.Fatalf("NewManifest: %v", err)
	}
	cm := m.Client("explicit")
	if cm == nil || cm.Consent.EmitGroupsClaim == nil || *cm.Consent.EmitGroupsClaim != true {
		t.Fatalf("explicit true not parsed: %+v", cm)
	}
	if !cm.ShouldEmitGroups() {
		t.Fatal("ShouldEmitGroups should be true when emit_groups_claim: true")
	}
}

// containsString is a tiny helper to keep tests stdlib-only.
func containsString(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
