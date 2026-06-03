// Package kratos implements glauth's Handler interface against an Ory
// Kratos backend. Identities live in Kratos; the bridge translates
// LDAP BIND and SEARCH to Kratos public-API and admin-API calls.
//
// Handler composition (per glauth pkg/handler.Handler):
//   - ldap.Binder        credential verification
//   - ldap.Searcher      entry lookup
//   - ldap.Adder         no-op (identities are managed via Kratos admin)
//   - ldap.Modifier      no-op
//   - ldap.Deleter       no-op
//   - ldap.Closer        connection cleanup
//   - HelperMaker        FindUser/FindGroup helpers used by glauth
//
// Notes:
//   - BIND uses Kratos /self-service/login with the API flow. We submit
//     identifier+password and treat 200 as success, 4xx as wrong creds,
//     5xx as Unavailable.
//   - SEARCH refreshes the identity cache on stale read, returns all
//     entries scoped to the request base; the LDAP server (with
//     EnforceLDAP set in main.go) applies the filter and scope post-hoc.
//   - Bind result cache holds positive results briefly (default 30s) to
//     absorb Apple TV / Jellyfin reconnect storms (Argon2 is expensive
//     per-call).
//   - Identity cache refreshes on stale read (default 30s). Kratos
//     admin mutations don't fire webhooks, so we poll.
package kratos

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/ldap"
)

// Config is the typed runtime config for the kratos handler. The
// binary's main package builds this from its config file.
type Config struct {
	// PublicURL is the public Kratos URL used for BIND verification.
	PublicURL string

	// AdminURL is the admin Kratos URL used for identity listing.
	AdminURL string

	// AdminToken authorizes admin API calls. Scope: identities:read.
	AdminToken string

	// BaseDN is the LDAP base, e.g., "dc=dunn,dc=dev".
	BaseDN string

	// IdentityCacheTTL controls how long admin-API listings are reused.
	IdentityCacheTTL time.Duration

	// BindCacheTTL controls how long positive bind results are cached.
	BindCacheTTL time.Duration

	// ServiceBindDN is the read-only search credential for non-OAuth LDAP
	// clients (e.g. Jellyfin on Apple TV). When non-empty, a bind with
	// this exact DN is verified against ServiceBindPassword in-process —
	// it does NOT correspond to any Kratos identity; humans are managed
	// only in Ory. If empty, the service-account bind feature is disabled.
	ServiceBindDN string

	// ServiceBindPassword is the resolved password for ServiceBindDN.
	// Must be non-empty when ServiceBindDN is set. Held in-memory only;
	// never logged.
	ServiceBindPassword string
}

// Handler implements glauth's Handler interface.
type Handler struct {
	cfg     Config
	client  *Client
	idCache *identityCache
	bdCache *bindCache
	mu      sync.RWMutex
}

// New constructs a Handler from a validated Config.
func New(cfg Config) (*Handler, error) {
	if cfg.PublicURL == "" || cfg.AdminURL == "" || cfg.AdminToken == "" {
		return nil, errors.New("kratos handler: public_url, admin_url, admin_token required")
	}
	// Normalize BaseDN once at construction time so that child-of-baseDN
	// comparisons are stable regardless of how the value arrived (env var,
	// config file, test code). TrimSpace only — lowercasing is done by
	// parseUsernameFromDN at call time and must not be applied globally here
	// because it could break case-sensitive DNs in some directories.
	cfg.BaseDN = strings.TrimSpace(cfg.BaseDN)
	if cfg.BaseDN == "" {
		return nil, errors.New("kratos handler: base_dn required")
	}
	if cfg.IdentityCacheTTL == 0 {
		cfg.IdentityCacheTTL = 30 * time.Second
	}
	if cfg.BindCacheTTL == 0 {
		cfg.BindCacheTTL = 30 * time.Second
	}

	return &Handler{
		cfg:     cfg,
		client:  newClient(cfg),
		idCache: newIdentityCache(cfg.IdentityCacheTTL),
		bdCache: newBindCache(cfg.BindCacheTTL),
	}, nil
}

// Bind verifies credentials by initiating a Kratos public-API login flow.
// On 200 from Kratos, bind succeeds. The Kratos session token returned
// by the login flow is discarded: we use the API for verification only.
func (h *Handler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	// Service-account short-circuit: if a read-only search DN is
	// configured (for non-OAuth clients like Jellyfin on Apple TV),
	// verify it in-process against the configured password. This DN is
	// NOT a Kratos identity; humans are managed only in Ory. Do not fall
	// through to Kratos for the service DN.
	if h.cfg.ServiceBindDN != "" {
		if strings.EqualFold(strings.TrimSpace(bindDN), strings.TrimSpace(h.cfg.ServiceBindDN)) {
			if subtle.ConstantTimeCompare([]byte(bindSimplePw), []byte(h.cfg.ServiceBindPassword)) == 1 {
				return ldap.LDAPResultSuccess, nil
			}
			return ldap.LDAPResultInvalidCredentials, nil
		}
	}

	username, err := parseUsernameFromDN(bindDN, h.cfg.BaseDN)
	if err != nil {
		return ldap.LDAPResultInvalidDNSyntax, err
	}

	if h.bdCache.verify(username, bindSimplePw) {
		return ldap.LDAPResultSuccess, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ok, err := h.client.VerifyPassword(ctx, username, bindSimplePw)
	if err != nil {
		if errors.Is(err, ErrUnavailable) {
			return ldap.LDAPResultUnavailable, err
		}
		return ldap.LDAPResultOperationsError, err
	}
	if !ok {
		return ldap.LDAPResultInvalidCredentials, nil
	}

	h.bdCache.store(username, bindSimplePw, true)
	return ldap.LDAPResultSuccess, nil
}

// Search returns LDAP entries built from cached Kratos identities. The
// LDAP server (configured with EnforceLDAP=true in main.go) applies
// scope and filter post-hoc, so this method may over-return.
//
// Security invariant: only the configured service-account DN may retrieve
// the full directory. Any other boundDN (including empty, meaning an
// anonymous or failed-bind connection) receives an empty result set with
// LDAPResultSuccess. If ServiceBindDN is unconfigured, all searches return
// empty (fail-closed default — a misconfiguration must not silently open
// the roster).
func (h *Handler) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	empty := ldap.ServerSearchResult{
		Entries:    []*ldap.Entry{},
		Referrals:  []string{},
		Controls:   []ldap.Control{},
		ResultCode: ldap.LDAPResultSuccess,
	}

	// Fail-closed: if no service DN is configured, no search is permitted.
	if h.cfg.ServiceBindDN == "" {
		return empty, nil
	}

	// Only the service-account DN may read the directory.
	if !strings.EqualFold(strings.TrimSpace(boundDN), strings.TrimSpace(h.cfg.ServiceBindDN)) {
		return empty, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := h.idCache.refresh(ctx, h.client); err != nil {
		// Stale entries are acceptable on transient Kratos outages.
	}

	entries := h.entries()

	return ldap.ServerSearchResult{
		Entries:    entries,
		Referrals:  []string{},
		Controls:   []ldap.Control{},
		ResultCode: ldap.LDAPResultSuccess,
	}, nil
}

// entries projects the cached identity list and group set into LDAP
// entries: one user entry per identity, one group entry per distinct
// group across the identity set.
func (h *Handler) entries() []*ldap.Entry {
	idents := h.idCache.snapshot()
	groups := h.idCache.allGroups()

	out := make([]*ldap.Entry, 0, len(idents)+len(groups))

	for _, ident := range idents {
		out = append(out, h.userEntry(&ident))
	}
	for name, members := range groups {
		out = append(out, h.groupEntry(name, members))
	}
	return out
}

func (h *Handler) userEntry(ident *Identity) *ldap.Entry {
	display := ident.Display
	if display == "" {
		display = ident.Username
	}

	memberOf := make([]string, 0, len(ident.Groups))
	for _, g := range ident.Groups {
		memberOf = append(memberOf, h.groupDN(g))
	}

	dn := h.userDN(ident.Username)
	attrs := []*ldap.EntryAttribute{
		{Name: "objectClass", Values: []string{"inetOrgPerson", "posixAccount"}},
		{Name: "uid", Values: []string{ident.Username}},
		{Name: "cn", Values: []string{display}},
		{Name: "sn", Values: []string{display}},
	}
	if ident.Email != "" {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "mail", Values: []string{ident.Email}})
	}
	if len(memberOf) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "memberOf", Values: memberOf})
	}
	return &ldap.Entry{DN: dn, Attributes: attrs}
}

func (h *Handler) groupEntry(name string, members []string) *ldap.Entry {
	memberDNs := make([]string, 0, len(members))
	for _, m := range members {
		memberDNs = append(memberDNs, h.userDN(m))
	}
	attrs := []*ldap.EntryAttribute{
		{Name: "objectClass", Values: []string{"groupOfNames"}},
		{Name: "cn", Values: []string{name}},
	}
	if len(memberDNs) > 0 {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "member", Values: memberDNs})
	}
	return &ldap.Entry{DN: h.groupDN(name), Attributes: attrs}
}

// escapeDNValue escapes a single RDN attribute value per RFC 4514 §2.4.
// Characters that must be escaped with a leading backslash:
//
//	" + , ; < = > \
//
// A leading '#' or leading space and a trailing space are also escaped.
// NUL bytes are encoded as \00.
//
// go-ldap/v3 is not a direct dependency of this module; glauth/ldap (the
// direct dep) does not expose an equivalent helper, so we implement it locally.
//
// Implementation note: we iterate over bytes (not runes) so that invalid UTF-8
// sequences are preserved verbatim rather than replaced with U+FFFD. RFC 4514
// requires the value to be a valid UTF-8 string in practice, but the escaper
// must be a pure byte-level pass-through for any bytes it does not recognise as
// needing escaping.
func escapeDNValue(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == 0x00:
			b.WriteString(`\00`)
		case c == '"' || c == '+' || c == ',' || c == ';' || c == '<' || c == '=' || c == '>' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case i == 0 && (c == '#' || c == ' '):
			// Leading '#' or leading space must be escaped.
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	// Trailing space must be escaped. The builder output is all bytes so we
	// can work on the raw string safely.
	out := b.String()
	if len(out) > 0 && out[len(out)-1] == ' ' {
		// Only escape if the trailing space is not already preceded by a backslash
		// that was itself escaped (i.e. "\\  " — the second space at the end).
		// In practice our loop above never writes a raw space after a backslash,
		// so a trailing space here is always unescaped.
		if len(out) < 2 || out[len(out)-2] != '\\' {
			out = out[:len(out)-1] + `\ `
		}
	}
	return out
}

func (h *Handler) userDN(username string) string {
	return "uid=" + escapeDNValue(username) + ",ou=users," + h.cfg.BaseDN
}

func (h *Handler) groupDN(name string) string {
	return "cn=" + escapeDNValue(name) + ",ou=groups," + h.cfg.BaseDN
}

// Add, Modify, Delete: identity changes go through Kratos admin API.
// LDAP write operations are refused.

func (h *Handler) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (ldap.LDAPResultCode, error) {
	return ldap.LDAPResultUnwillingToPerform, errors.New("identities are managed via Kratos admin API")
}

func (h *Handler) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (ldap.LDAPResultCode, error) {
	return ldap.LDAPResultUnwillingToPerform, errors.New("identities are managed via Kratos admin API")
}

func (h *Handler) Delete(boundDN, deleteDN string, conn net.Conn) (ldap.LDAPResultCode, error) {
	return ldap.LDAPResultUnwillingToPerform, errors.New("identities are managed via Kratos admin API")
}

func (h *Handler) Close(boundDN string, conn net.Conn) error {
	return nil
}

// FindUser is glauth's HelperMaker hook used during search composition.
// We project a Kratos identity onto the config.User shape glauth uses
// internally. Password fields are intentionally empty: bind goes
// through Bind() against Kratos directly.
func (h *Handler) FindUser(ctx context.Context, userName string, searchByUPN bool) (bool, config.User, error) {
	if err := h.idCache.refresh(ctx, h.client); err != nil {
		// fall through to whatever the cache holds
	}

	want := userName
	if searchByUPN {
		// UPN is "user@domain"; we match the local part if a Kratos
		// identity uses that as username, or fall back to email.
		if at := strings.Index(want, "@"); at > 0 {
			localPart := want[:at]
			if ident := h.idCache.findByUsername(localPart); ident != nil {
				return true, h.toConfigUser(ident), nil
			}
		}
		for _, ident := range h.idCache.snapshot() {
			if strings.EqualFold(ident.Email, want) {
				i := ident
				return true, h.toConfigUser(&i), nil
			}
		}
		return false, config.User{}, nil
	}

	if ident := h.idCache.findByUsername(want); ident != nil {
		return true, h.toConfigUser(ident), nil
	}
	return false, config.User{}, nil
}

func (h *Handler) toConfigUser(ident *Identity) config.User {
	display := ident.Display
	if display == "" {
		display = ident.Username
	}
	return config.User{
		Name:        ident.Username,
		Mail:        ident.Email,
		GivenName:   display,
		SN:          display,
		CustomAttrs: map[string]interface{}{},
	}
}

// FindGroup derives groups from the union of all identities'
// metadata_admin.groups.
func (h *Handler) FindGroup(ctx context.Context, groupName string) (bool, config.Group, error) {
	if err := h.idCache.refresh(ctx, h.client); err != nil {
		// serve stale
	}
	groups := h.idCache.allGroups()
	if _, ok := groups[groupName]; !ok {
		return false, config.Group{}, nil
	}
	return true, config.Group{Name: groupName}, nil
}

// FlushBindCacheFor (MEDIUM-5) drops bind-cache entries so the next bind
// for the named identity hits Kratos directly (Argon2 verify) rather
// than the cached positive result. Called from the admin HTTP endpoint
// after the consent service signals a force-relogin.
//
// Bind cache keys mix in the password, so we cannot match by username
// alone without storing the password (which we deliberately don't). The
// implementation drops the entire bind cache; rebuild cost is low at
// family scale.
func (h *Handler) FlushBindCacheFor(username string) {
	h.bdCache.FlushOne(username)
}
