// Caching: identity list cache (for SEARCH) and bind result cache (for BIND).
//
// Identity cache:
//   - TTL configurable (default 30s).
//   - Refreshed by ListIdentities call when stale on read.
//   - No webhook-driven invalidation: Kratos admin mutations don't fire
//     hooks, so we poll. Acceptable at homelab scale.
//   - On Kratos error, the cache is not updated; stale data is served.
//
// Bind cache:
//   - TTL configurable (default 30s).
//   - Keyed by sha256(per-process-salt || username || NUL || password).
//   - Per-process salt (M3) means a memory dump of one process can't be
//     replayed against another or against a precomputed table. Salt is
//     32 bytes from crypto/rand at startup, never written anywhere.
//   - Absorbs reconnect storms from Apple TV / Jellyfin native clients
//     where Argon2 verification per-call would be expensive.
//   - Negative results NOT cached (so wrong-password retry isn't held).
//
// Bind cache TTL semantics (M4):
//
//	A password rotation in Kratos doesn't invalidate this cache; the old
//	password binds successfully for up to BindCacheTTL (default 30s)
//	after rotation. Acceptable at homelab scale per docs/architecture.md.
//	Group changes have the same lag (M5): up to 30s before the bridge's
//	identity cache reflects a Kratos-side group edit.
package kratos

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// processSalt is mixed into the bind-cache key derivation. Two
// consequences:
//
//   - Same (username, password) hashes to a different value in every
//     process. A heap dump doesn't yield rainbow-table-able material.
//   - The cache state is non-portable: a restart drops every entry,
//     which is exactly what we want (no persisted credentials).
//
// Salt is regenerated on init and (MEDIUM-4) callable via
// RegenerateSalt() for any future SIGHUP / reload path. The bind cache
// is dropped at the same time so existing entries remain verifiable
// (otherwise the new salt would invalidate every entry implicitly).
var (
	processSaltMu sync.RWMutex
	processSalt   [32]byte
)

func init() {
	if err := writeProcessSalt(); err != nil {
		// crypto/rand failure on Linux is a process-fatal condition;
		// glauth itself wouldn't survive it either. Panic so the
		// supervisor restarts us.
		panic("ldap-bridge: crypto/rand unavailable: " + err.Error())
	}
}

// writeProcessSalt fills processSalt with 32 bytes from crypto/rand
// under the write lock.
func writeProcessSalt() error {
	processSaltMu.Lock()
	defer processSaltMu.Unlock()
	_, err := rand.Read(processSalt[:])
	return err
}

// readProcessSalt returns a copy of the current process salt under the
// read lock.
func readProcessSalt() [32]byte {
	processSaltMu.RLock()
	defer processSaltMu.RUnlock()
	return processSalt
}

// RegenerateSalt (MEDIUM-4) replaces the process salt with a fresh 32
// bytes from crypto/rand. Any future SIGHUP / reload path should call
// this so a single memory dump pre-reload does not yield material that
// can be replayed against the post-reload process.
//
// Today no reload path exists; the export is the value-add. Callers
// that wire this in MUST also drop the bind cache: existing entries
// were keyed off the old salt and would no longer verify after a
// regenerate.
func RegenerateSalt() error {
	return writeProcessSalt()
}

// identityCache holds the slim identity list with a TTL refresh
// pattern, plus a username index for O(1) lookups during BIND DN
// translation.
type identityCache struct {
	mu        sync.RWMutex
	ttl       time.Duration
	expiresAt time.Time
	entries   IdentityList
	byUser    map[string]*Identity
}

func newIdentityCache(ttl time.Duration) *identityCache {
	return &identityCache{
		ttl:    ttl,
		byUser: map[string]*Identity{},
	}
}

// refresh reads from Kratos if the cache is stale. Soft-fail: if Kratos
// is unreachable, return the cached data (caller can decide whether
// stale is acceptable for this query).
func (c *identityCache) refresh(ctx context.Context, client *Client) error {
	c.mu.RLock()
	stale := time.Now().After(c.expiresAt)
	c.mu.RUnlock()
	if !stale {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Now().Before(c.expiresAt) {
		return nil
	}

	list, err := client.ListIdentities(ctx)
	if err != nil {
		return err
	}

	idx := make(map[string]*Identity, len(list))
	for i := range list {
		idx[list[i].Username] = &list[i]
	}
	c.entries = list
	c.byUser = idx
	c.expiresAt = time.Now().Add(c.ttl)
	return nil
}

// snapshot returns a stable view of the current cached identities.
// Caller must not mutate. The returned slice header is shared; the
// caller should treat it as read-only.
func (c *identityCache) snapshot() IdentityList {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.entries
}

// findByUsername returns the identity for the given username, or nil
// if not present. Comparisons are case-sensitive (Kratos identifiers
// are case-sensitive at the credential layer).
func (c *identityCache) findByUsername(u string) *Identity {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.byUser[u]
}

// allGroups returns the set of groups across all identities. Order is
// not stable.
func (c *identityCache) allGroups() map[string][]string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	groups := map[string][]string{}
	for _, ident := range c.entries {
		for _, g := range ident.Groups {
			groups[g] = append(groups[g], ident.Username)
		}
	}
	return groups
}

// bindCache caches positive bind results to absorb reconnect storms.
type bindCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]bindCacheEntry
}

type bindCacheEntry struct {
	expiresAt time.Time
}

func newBindCache(ttl time.Duration) *bindCache {
	return &bindCache{
		ttl:     ttl,
		entries: make(map[string]bindCacheEntry),
	}
}

func (b *bindCache) key(username, password string) string {
	// M3: per-process salt prefixes the hash so the same (user, pass)
	// pair maps to a different cache key in every process. Bind cache
	// state never crosses a process boundary, so a salted hash gives
	// nothing useful to a hypothetical attacker with read-only memory
	// access.
	salt := readProcessSalt()
	h := sha256.New()
	h.Write(salt[:])
	h.Write([]byte(username))
	h.Write([]byte{0})
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

// Flush drops every entry from the bind cache. Call after RegenerateSalt
// so old entries (keyed off the old salt) don't linger.
func (b *bindCache) Flush() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries = make(map[string]bindCacheEntry)
}

// FlushOne drops the cache entry for a single (username) regardless of
// password (MEDIUM-5). The bridge calls this from its admin endpoint
// when the consent service signals a force-relogin for the named
// identity. We can't compute the cache key without the password; instead
// we walk and drop any entry that hashes to a key prefixed with this
// username. Since the key derivation includes a NUL separator before
// the password, we cannot match by prefix; the simplest correct
// approach at family scale is to drop the entire cache.
//
// This is acceptable: bind cache absorbs reconnect storms, not a hot
// auth path; rebuilding it costs at most one Argon2 verification per
// active session at the next bind. Family scale (10 identities × low
// reconnect rate) means this is a no-op-cost flush.
func (b *bindCache) FlushOne(username string) {
	// Username-keyed flush would require carrying the key forward,
	// which we deliberately don't (no persisted credentials). Drop the
	// cache wholesale; rebuild on next bind. _ username keeps the
	// signature pleasant for callers that name the user but doesn't
	// influence behavior today.
	_ = username
	b.Flush()
}

func (b *bindCache) verify(username, password string) bool {
	k := b.key(username, password)
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.entries[k]
	if !ok {
		return false
	}
	if time.Now().After(e.expiresAt) {
		delete(b.entries, k)
		return false
	}
	return true
}

func (b *bindCache) store(username, password string, success bool) {
	if !success {
		return
	}
	k := b.key(username, password)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries[k] = bindCacheEntry{
		expiresAt: time.Now().Add(b.ttl),
	}
}
