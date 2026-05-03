// Package kratos implements glauth's Handler interface against an Ory
// Kratos backend. Identities live in Kratos; the bridge translates
// LDAP BIND and SEARCH to Kratos public-API and admin-API calls.
//
// Handler composition (per glauth v2.4+):
//   - ldap.Binder        — credential verification (this package)
//   - ldap.Searcher      — entry lookup (this package)
//   - ldap.Adder         — no-op (identities are managed via Kratos admin)
//   - ldap.Modifier      — no-op
//   - ldap.Deleter       — no-op
//   - ldap.Closer        — connection cleanup
//   - HelperMaker        — provides FindUser/FindGroup helpers used by glauth
//
// CRITICAL design notes (from feasibility-q1-kratos-bind.md):
//   - Bind uses Kratos /self-service/login API flow with aal=aal1.
//     Setting aal>1 risks identity=null in whoami responses for
//     MFA-enabled users (won't bite Bind directly, but matters for
//     consistency with the cached identity lookup).
//   - Bind result is cached briefly (~30s) per identity to absorb
//     Apple TV / Jellyfin reconnect storms (Argon2 is expensive).
//   - Search uses Kratos /admin/identities. Bridge admin token is
//     scoped identity-read-only.
//   - Identity cache TTL ~30s with polling refresh. Kratos admin
//     mutations don't fire webhooks, so push-invalidation isn't
//     possible without that contribution upstream.
package kratos

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	glauth "github.com/glauth/glauth/v2/pkg/handler"
)

// Config is unmarshalled from glauth's config file under
// `[backend.handler.kratos]` once the handler is registered.
type Config struct {
	// Public Kratos URL for self-service flows (BIND target).
	PublicURL string `mapstructure:"public_url"`

	// Admin Kratos URL for identity listing (SEARCH target).
	AdminURL string `mapstructure:"admin_url"`

	// Identity-read-only admin API token. Scope: identities:read.
	// Source: Kratos admin-token issuance + Bitwarden-managed env var.
	AdminToken string `mapstructure:"admin_token"`

	// LDAP base DN, e.g., "dc=dunn,dc=dev"
	BaseDN string `mapstructure:"base_dn"`

	// Cache TTL for identity list and bind results.
	IdentityCacheTTL time.Duration `mapstructure:"identity_cache_ttl"`
	BindCacheTTL     time.Duration `mapstructure:"bind_cache_ttl"`
}

// Handler implements glauth's Handler composition.
type Handler struct {
	cfg     Config
	client  *Client
	idCache *identityCache
	bdCache *bindCache
	mu      sync.RWMutex
}

// New constructs a Handler. Registered with glauth via the init()
// in this package.
func New(cfg Config) (*Handler, error) {
	if cfg.PublicURL == "" || cfg.AdminURL == "" || cfg.AdminToken == "" {
		return nil, errors.New("kratos handler: public_url, admin_url, admin_token required")
	}
	if cfg.BaseDN == "" {
		return nil, errors.New("kratos handler: base_dn required")
	}
	if cfg.IdentityCacheTTL == 0 {
		cfg.IdentityCacheTTL = 30 * time.Second
	}
	if cfg.BindCacheTTL == 0 {
		cfg.BindCacheTTL = 30 * time.Second
	}

	h := &Handler{
		cfg:     cfg,
		client:  newClient(cfg),
		idCache: newIdentityCache(cfg.IdentityCacheTTL),
		bdCache: newBindCache(cfg.BindCacheTTL),
	}
	return h, nil
}

// Bind verifies credentials by initiating a Kratos public-API login flow.
// On 200 from Kratos, bind succeeds. The Kratos session token returned by
// the login flow is discarded — we only use the API for verification.
func (h *Handler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	username, err := parseUsernameFromDN(bindDN, h.cfg.BaseDN)
	if err != nil {
		return ldap.LDAPResultInvalidDNSyntax, err
	}

	// Check bind cache first (absorbs Apple TV reconnect storms).
	if h.bdCache.verify(username, bindSimplePw) {
		return ldap.LDAPResultSuccess, nil
	}

	// TODO: real implementation
	// 1. POST <PublicURL>/self-service/login/api -> get flow_id
	// 2. POST <PublicURL>/self-service/login?flow=<flow_id>
	//    body: {"method":"password","identifier":username,"password":pw}
	//    headers: Accept: application/json, Content-Type: application/json
	// 3. 200 -> success; cache (username,pw_hash,success); return LDAPResultSuccess
	// 4. 4xx -> failure; do not cache; return LDAPResultInvalidCredentials
	// 5. 5xx -> error; return LDAPResultUnavailable
	//
	// Edge case: identity has MFA enabled and Kratos required_aal=highest_available
	// would return 200 with session.identity=null. Kratos.yml sets
	// session.whoami.required_aal=aal1 to avoid this. Bind only uses login flow,
	// not whoami, so this is informational.

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ok, err := h.client.VerifyPassword(ctx, username, bindSimplePw)
	if err != nil {
		return ldap.LDAPResultUnavailable, err
	}
	if !ok {
		return ldap.LDAPResultInvalidCredentials, nil
	}

	h.bdCache.store(username, bindSimplePw, true)
	return ldap.LDAPResultSuccess, nil
}

// Search returns LDAP entries by translating from cached Kratos identities.
// Filter and base DN are applied per glauth's normal filter logic.
func (h *Handler) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	// TODO: real implementation
	// 1. Refresh cache if stale (h.idCache.refresh)
	// 2. Build a slice of *ldap.Entry from h.idCache.entries:
	//      DN: uid=<traits.username>,ou=users,<base_dn>
	//      Attributes:
	//        objectClass: [inetOrgPerson, posixAccount]
	//        uid: traits.username
	//        cn: traits.displayName || traits.username
	//        mail: traits.email
	//        memberOf: [cn=<group>,ou=groups,<base_dn> for group in metadata_admin.groups]
	// 3. Filter through glauth's filter helpers using searchReq.Filter
	// 4. Return matched subset in ServerSearchResult

	if err := h.idCache.refresh(context.Background(), h.client); err != nil {
		// Stale cache returns are acceptable on transient Kratos outages
		// for read paths. Log and continue.
	}

	entries := h.idCache.entriesForBase(searchReq.BaseDN, h.cfg.BaseDN)
	filtered := applyFilter(entries, searchReq.Filter)

	return ldap.ServerSearchResult{
		Entries:    filtered,
		Referrals:  []string{},
		Controls:   []ldap.Control{},
		ResultCode: ldap.LDAPResultSuccess,
	}, nil
}

// Add, Modify, Delete: identity changes go through Kratos admin API, not LDAP.
// We return Unwilling To Perform on these operations.

func (h *Handler) Add(req ldap.AddRequest, conn net.Conn) (ldap.LDAPResultCode, error) {
	return ldap.LDAPResultUnwillingToPerform, errors.New("identities are managed via Kratos admin API, not LDAP")
}

func (h *Handler) Modify(req ldap.ModifyRequest, conn net.Conn) (ldap.LDAPResultCode, error) {
	return ldap.LDAPResultUnwillingToPerform, errors.New("identities are managed via Kratos admin API, not LDAP")
}

func (h *Handler) Delete(boundDN string, deleteDN string, conn net.Conn) (ldap.LDAPResultCode, error) {
	return ldap.LDAPResultUnwillingToPerform, errors.New("identities are managed via Kratos admin API, not LDAP")
}

func (h *Handler) Close(boundDN string, conn net.Conn) error {
	// Per-connection cleanup if any. Currently no per-connection state.
	return nil
}

// HelperMaker glauth interface — for the FindUser / FindGroup helpers
// glauth uses internally during search.
func (h *Handler) FindUser(username string, searchByUPN bool) (bool, glauth.User, error) {
	// TODO: lookup from identity cache; return User struct populated from Kratos identity
	return false, glauth.User{}, errors.New("not implemented")
}

func (h *Handler) FindGroup(groupName string) (bool, glauth.Group, error) {
	// TODO: derive groups from union of all identities' metadata_admin.groups
	return false, glauth.Group{}, errors.New("not implemented")
}

// Imports placeholders below; real go.mod resolves these.
type net struct{ Conn struct{} }
