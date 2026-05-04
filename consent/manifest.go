package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// ClientManifest mirrors the on-disk hydra/clients/<id>.yaml shape after
// the C3/D6 namespace split. Top-level keys are `oidc:` (Hydra-bound) and
// `consent:` (consent-service-only). Unknown fields are tolerated by the
// yaml parser so future additions on either side don't break loaders.
type ClientManifest struct {
	OIDC    OIDCConfig    `yaml:"oidc"`
	Consent ConsentConfig `yaml:"consent"`

	// SourcePath is the file the manifest was loaded from. Populated by
	// the loader, not the yaml.
	SourcePath string `yaml:"-"`
}

// OIDCConfig is the Hydra-bound block. apply-clients.sh forwards this
// (plus client_secret from env) to the Hydra admin API. Anything not in
// this block must not be sent to Hydra.
type OIDCConfig struct {
	ClientID                 string   `yaml:"client_id"`
	ClientName               string   `yaml:"client_name"`
	GrantTypes               []string `yaml:"grant_types,omitempty"`
	ResponseTypes            []string `yaml:"response_types,omitempty"`
	Scope                    string   `yaml:"scope,omitempty"`
	RedirectURIs             []string `yaml:"redirect_uris,omitempty"`
	PostLogoutRedirectURIs   []string `yaml:"post_logout_redirect_uris,omitempty"`
	TokenEndpointAuthMethod  string   `yaml:"token_endpoint_auth_method,omitempty"`
	Audience                 []string `yaml:"audience,omitempty"`
	SkipConsent              bool     `yaml:"skip_consent,omitempty"`

	// BackchannelLogoutURI is the per-client logout endpoint per the
	// OIDC Back-Channel Logout 1.0 spec. Apps that support it accept a
	// signed JWT logout token and invalidate the local session. Apps
	// without back-channel logout (Tailscale custom OIDC, vLLM bearer
	// auth) leave this empty.
	BackchannelLogoutURI string `yaml:"backchannel_logout_uri,omitempty"`

	// BackchannelLogoutSessionRequired flips the OIDC Back-Channel Logout
	// "include sid claim" toggle. Most apps don't track per-client
	// sessions, so the default (false) is fine. Set true for apps that
	// require sid in the logout token.
	BackchannelLogoutSessionRequired bool `yaml:"backchannel_logout_session_required,omitempty"`
}

// ConsentConfig is the consent-service-only block. None of these fields
// are forwarded to Hydra. Putting them under their own namespace removes
// the C3 risk of pushing unknown fields at Hydra's client object.
type ConsentConfig struct {
	// Roles declares the per-app role enum used for claim emission.
	Roles map[string]Role `yaml:"roles,omitempty"`

	// GroupRoleMap maps identity group name to a role declared in Roles.
	GroupRoleMap map[string]string `yaml:"group_role_map,omitempty"`

	// EmitGroupsClaim controls whether the consent service injects the
	// auto `groups` claim (sourced from metadata_admin.groups) into the
	// id_token. Pointer-to-bool so a missing key in yaml means "default
	// true" and an explicit `false` suppresses the claim. Apps that do
	// not consume groups (Tailscale custom OIDC, vLLM bearer tokens) set
	// this to false to avoid bloating the id_token.
	//
	// The role's claim_emit map is unaffected; only the auto-emitted
	// groups claim from the default claim set is suppressed.
	EmitGroupsClaim *bool `yaml:"emit_groups_claim,omitempty"`

	// SkipAccessCheck disables the access-<client_id> group enforcement
	// in handleConsent. Reserved for future use; no manifest sets it
	// today. Leaving the gate on is the secure-by-default posture (D2).
	SkipAccessCheck bool `yaml:"skip_access_check,omitempty"`
}

// ShouldEmitGroups reports whether the consent service should inject the
// auto `groups` claim for this client. Default is true; only an explicit
// `emit_groups_claim: false` in the yaml suppresses it.
func (m *ClientManifest) ShouldEmitGroups() bool {
	if m == nil || m.Consent.EmitGroupsClaim == nil {
		return true
	}
	return *m.Consent.EmitGroupsClaim
}

// ClientID returns the client_id from the OIDC block. Convenience accessor;
// every caller used to read m.ClientID before the namespace migration.
func (m *ClientManifest) ClientID() string {
	if m == nil {
		return ""
	}
	return m.OIDC.ClientID
}

// Role is one entry in ConsentConfig.Roles.
//
// ClaimEmit is a free-form map of claim_name -> value injected into the
// id_token when the role resolves for a user. Apps decide how to read
// these (top-level claims, namespaced under a role object, etc.) via their
// configured claim_emit shape.
type Role struct {
	Description string         `yaml:"description"`
	ClaimEmit   map[string]any `yaml:"claim_emit"`
}

// Manifest is the in-memory registry of client manifests loaded from
// hydra/clients/*.yaml. Reload() re-reads from disk; lookups are
// goroutine-safe via the RWMutex.
type Manifest struct {
	dir string

	mu      sync.RWMutex
	clients map[string]*ClientManifest // keyed by client_id (lowercased)
}

// NewManifest creates a Manifest backed by dir and performs an initial
// load. A load error is returned; the manifest is left empty in that case.
func NewManifest(dir string) (*Manifest, error) {
	m := &Manifest{dir: dir, clients: map[string]*ClientManifest{}}
	if err := m.Reload(); err != nil {
		return m, err
	}
	return m, nil
}

// Dir returns the source directory.
func (m *Manifest) Dir() string {
	return m.dir
}

// Reload re-reads every *.yaml under the manifest dir and replaces the
// in-memory map atomically. A parse error on any file aborts the reload
// without mutating the existing state, so a partial-bad reload can't take
// down a working service.
//
// M2: Reload runs the full ValidateManifests lint pass on the candidate
// set BEFORE swapping. A reload that introduces (e.g.) an undeclared role
// in group_role_map is rejected with prior state intact, so the next
// consent flow doesn't silently drop role claims.
func (m *Manifest) Reload() error {
	if m.dir == "" {
		return errors.New("manifest dir is empty")
	}
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return fmt.Errorf("read manifest dir %s: %w", m.dir, err)
	}

	next := map[string]*ClientManifest{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(m.dir, name)
		cm, err := loadClientManifest(path)
		if err != nil {
			return fmt.Errorf("load %s: %w", path, err)
		}
		if cm.OIDC.ClientID == "" {
			return fmt.Errorf("load %s: oidc.client_id is empty", path)
		}
		key := strings.ToLower(cm.OIDC.ClientID)
		if dup, ok := next[key]; ok {
			return fmt.Errorf("duplicate client_id %q in %s and %s", key, dup.SourcePath, path)
		}
		next[key] = cm
	}

	// M2: validate the candidate set before swap. A draft manifest dir
	// with an undeclared role or missing audience aborts the reload
	// rather than silently breaking consent for the affected client(s).
	if errs := validateClients(next); len(errs) > 0 {
		// Surface the first finding; the operator inspects logs for the
		// full set via runValidate() if needed.
		return fmt.Errorf("manifest validation failed (%d finding(s)); first: %w", len(errs), errs[0])
	}

	m.mu.Lock()
	m.clients = next
	m.mu.Unlock()
	return nil
}

// Client returns the manifest for a client_id, or nil if not loaded.
func (m *Manifest) Client(clientID string) *ClientManifest {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.clients[strings.ToLower(clientID)]
}

// Clients returns a snapshot of all loaded manifests.
func (m *Manifest) Clients() []*ClientManifest {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*ClientManifest, 0, len(m.clients))
	for _, c := range m.clients {
		out = append(out, c)
	}
	return out
}

// LookupRole resolves the role to apply for clientID given a user identity.
//
// Resolution:
//  1. metadata_admin.roles[clientID] (override). If the named role is
//     declared in the client manifest's Roles map, it wins.
//  2. metadata_admin.groups walked in declared order. The first group
//     present in the client manifest's GroupRoleMap, whose mapped role
//     also exists in Roles, wins.
//  3. ok=false. Caller falls back to groups-only claim emission.
//
// Returns the role name, the role's claim_emit map (a copy, safe to
// mutate), and ok.
func (m *Manifest) LookupRole(clientID string, meta map[string]any) (string, map[string]any, bool) {
	cm := m.Client(clientID)
	if cm == nil || len(cm.Consent.Roles) == 0 {
		return "", nil, false
	}

	if name, ok := overrideRole(meta, clientID); ok {
		if role, declared := cm.Consent.Roles[name]; declared {
			return name, copyClaimEmit(role.ClaimEmit), true
		}
		// Override names a role that's not declared in the manifest.
		// Fall through to derivation rather than emit nothing; this keeps
		// behavior predictable when an admin typos a role name.
	}

	if len(cm.Consent.GroupRoleMap) > 0 {
		for _, g := range identityGroups(meta) {
			roleName, mapped := cm.Consent.GroupRoleMap[g]
			if !mapped {
				continue
			}
			if role, declared := cm.Consent.Roles[roleName]; declared {
				return roleName, copyClaimEmit(role.ClaimEmit), true
			}
		}
	}
	return "", nil, false
}

// overrideRole reads metadata_admin.roles[clientID] tolerating the
// map[string]any shape encoding/json gives us when decoding into a
// generic map.
func overrideRole(meta map[string]any, clientID string) (string, bool) {
	if meta == nil {
		return "", false
	}
	raw, ok := meta["roles"]
	if !ok {
		return "", false
	}
	roles, ok := raw.(map[string]any)
	if !ok {
		return "", false
	}
	v, ok := roles[strings.ToLower(clientID)]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

// identityGroups walks metadata_admin.groups preserving declared order.
// This is the order users care about for first-match semantics; the
// client manifest's GroupRoleMap is consulted by name, so its yaml map
// ordering does not matter.
func identityGroups(meta map[string]any) []string {
	if meta == nil {
		return nil
	}
	raw, ok := meta["groups"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// copyClaimEmit returns a shallow copy of claim_emit so callers can merge
// it into a session map without aliasing the manifest's storage.
func copyClaimEmit(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// legacyManifestProbe is the smallest decode that detects the pre-namespace
// flat shape, so the loader can refuse the file with a clear error rather
// than silently parsing into an empty ClientManifest.
type legacyManifestProbe struct {
	ClientID    string         `yaml:"client_id"`
	ClientName  string         `yaml:"client_name"`
	GrantTypes  []string       `yaml:"grant_types"`
	Roles       map[string]any `yaml:"roles"`
	GroupMap    map[string]any `yaml:"group_role_map"`
	EmitGroups  any            `yaml:"emit_groups_claim"`
	OIDCBlock   any            `yaml:"oidc"`
	ConsentBlk  any            `yaml:"consent"`
}

func loadClientManifest(path string) (*ClientManifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Probe for the legacy flat shape. If oidc:/consent: are absent and
	// any of the legacy top-level keys are present, refuse loudly: silent
	// migration would mean apps boot with an empty manifest.
	probe := legacyManifestProbe{}
	if err := yaml.Unmarshal(b, &probe); err == nil {
		hasNamespace := probe.OIDCBlock != nil || probe.ConsentBlk != nil
		hasLegacy := probe.ClientID != "" || probe.ClientName != "" ||
			len(probe.GrantTypes) > 0 || len(probe.Roles) > 0 ||
			len(probe.GroupMap) > 0 || probe.EmitGroups != nil
		if hasLegacy && !hasNamespace {
			return nil, fmt.Errorf(
				"manifest %s uses the pre-namespace flat shape "+
					"(top-level client_id / roles / group_role_map). "+
					"Migrate to the oidc:/consent: shape; see "+
					"hydra/clients/keep.yaml for an example",
				path)
		}
	}

	cm := &ClientManifest{}
	if err := yaml.Unmarshal(b, cm); err != nil {
		return nil, fmt.Errorf("yaml unmarshal: %w", err)
	}
	cm.SourcePath = path
	return cm, nil
}

// ValidateManifests performs a static-lint pass against the loaded set:
//   - oidc.client_id must be non-empty (already enforced at load).
//   - oidc.audience must be non-empty (H4: id_token aud verification
//     depends on it; missing aud means apps can't validate the token).
//   - oidc.audience must contain at least one URI whose host matches one
//     of redirect_uris' hosts. Catches typos that would otherwise let
//     Hydra issue tokens nobody can validate.
//   - Every value in consent.group_role_map must be a key in consent.roles.
//   - Every claim_emit must be non-nil for declared roles.
//   - emit_groups_claim: false paired with a role claim_emit that includes
//     a `groups` key is a contradiction; warn (M10).
//
// Returns one error per problem; an empty slice means clean.
func (m *Manifest) ValidateManifests() []error {
	return validateClients(m.snapshotClientMap())
}

// snapshotClientMap returns the in-memory client map under read lock. Used
// by ValidateManifests so it shares one validator with the pre-swap path
// in Reload.
func (m *Manifest) snapshotClientMap() map[string]*ClientManifest {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]*ClientManifest, len(m.clients))
	for k, v := range m.clients {
		out[k] = v
	}
	return out
}

// validateClients runs the lint pass over a candidate set. Reload (M2)
// and ValidateManifests both call into this so the rules stay in one
// place.
func validateClients(set map[string]*ClientManifest) []error {
	var errs []error
	for _, cm := range set {
		if cm.OIDC.ClientID == "" {
			errs = append(errs, fmt.Errorf("%s: oidc.client_id is empty", cm.SourcePath))
		}
		if len(cm.OIDC.Audience) == 0 {
			errs = append(errs, fmt.Errorf("%s: oidc.audience is empty (every client needs an audience for id_token aud verification)", cm.SourcePath))
		} else if len(cm.OIDC.RedirectURIs) > 0 {
			if !audienceMatchesRedirect(cm.OIDC.Audience, cm.OIDC.RedirectURIs) {
				errs = append(errs, fmt.Errorf("%s: no oidc.audience host matches any redirect_uris host (apps verify id_token.aud against their own URL)", cm.SourcePath))
			}
		}
		for groupName, roleName := range cm.Consent.GroupRoleMap {
			if _, ok := cm.Consent.Roles[roleName]; !ok {
				errs = append(errs, fmt.Errorf("%s: consent.group_role_map[%q] points at role %q which is not declared in consent.roles", cm.SourcePath, groupName, roleName))
			}
		}
		for roleName, role := range cm.Consent.Roles {
			if role.ClaimEmit == nil {
				errs = append(errs, fmt.Errorf("%s: consent.roles[%q] has no claim_emit", cm.SourcePath, roleName))
			}
		}
		// M10: emit_groups_claim: false + role claim_emit.groups is a
		// silent contradiction. The role's groups will land in the
		// token even though the operator suppressed the auto claim.
		// Surfaced as a lint finding so Reload's M2 pre-swap check
		// rejects a draft manifest with this misconfig before the
		// contradictory shape ships in an issued id_token. The original
		// adversarial-review framing called for a warning-not-error;
		// promoted to error here because there's no legitimate reason
		// to set both flags AND the M2 reload guard means production
		// state never holds a contradictory manifest.
		if cm.Consent.EmitGroupsClaim != nil && !*cm.Consent.EmitGroupsClaim {
			for roleName, role := range cm.Consent.Roles {
				if role.ClaimEmit == nil {
					continue
				}
				if _, hasGroups := role.ClaimEmit["groups"]; hasGroups {
					errs = append(errs, fmt.Errorf("%s: consent.emit_groups_claim:false but consent.roles[%q].claim_emit.groups is set; the role's groups will still be emitted", cm.SourcePath, roleName))
				}
			}
		}
	}
	return errs
}

// audienceMatchesRedirect reports whether at least one audience entry has
// the same host as at least one redirect_uri. Apps verify id_token.aud
// against their own origin; a manifest where the two never overlap will
// emit unverifiable tokens.
func audienceMatchesRedirect(audience, redirectURIs []string) bool {
	hosts := map[string]struct{}{}
	for _, r := range redirectURIs {
		u, err := url.Parse(r)
		if err != nil || u.Host == "" {
			continue
		}
		hosts[strings.ToLower(u.Host)] = struct{}{}
	}
	if len(hosts) == 0 {
		// No usable redirect host (e.g., custom-scheme app:// only). Skip
		// this sub-check rather than false-flag.
		return true
	}
	for _, a := range audience {
		u, err := url.Parse(a)
		if err != nil {
			continue
		}
		host := u.Host
		if host == "" {
			// Bare hostname or scheme-less audience. Compare directly.
			host = strings.TrimSpace(a)
		}
		if _, ok := hosts[strings.ToLower(host)]; ok {
			return true
		}
	}
	return false
}

