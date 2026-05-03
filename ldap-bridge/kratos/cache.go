// Caching: identity list cache (for SEARCH) and bind result cache (for BIND).
//
// Identity cache:
//   - TTL ~30s (configurable)
//   - Refreshed by ListIdentities call when stale on read
//   - No webhook-driven invalidation: Kratos admin mutations don't fire
//     hooks, so we poll. Acceptable at homelab scale.
//
// Bind cache:
//   - TTL ~30s (configurable)
//   - Keyed by (username, sha256(password)) -> bool
//   - Absorbs reconnect storms from Apple TV / Jellyfin native clients
//     where Argon2 verification per-call would be expensive
//   - Negative results NOT cached (so wrong-password retry isn't held)
package kratos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// identityCache holds the slim identity list with a TTL refresh pattern.
type identityCache struct {
	mu        sync.RWMutex
	ttl       time.Duration
	expiresAt time.Time
	entries   IdentityList
}

func newIdentityCache(ttl time.Duration) *identityCache {
	return &identityCache{ttl: ttl}
}

// refresh reads from Kratos if the cache is stale. Soft-fail: if Kratos
// is unreachable, return cached data (caller can decide whether stale is
// acceptable for this query).
func (c *identityCache) refresh(ctx context.Context, client *Client) error {
	c.mu.RLock()
	stale := time.Now().After(c.expiresAt)
	c.mu.RUnlock()
	if !stale {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Re-check after acquiring write lock
	if time.Now().Before(c.expiresAt) {
		return nil
	}

	list, err := client.ListIdentities(ctx)
	if err != nil {
		// Don't update cache on error; serve stale.
		return err
	}
	c.entries = list
	c.expiresAt = time.Now().Add(c.ttl)
	return nil
}

// entriesForBase returns LDAP entries built from the cached identity list.
// Caller passes the search base DN; we filter by suffix match.
func (c *identityCache) entriesForBase(searchBaseDN, configBaseDN string) []interface{} {
	// TODO: build *ldap.Entry slice with the schema mapping documented
	// in handler.go (uid, cn, mail, memberOf, objectClass).
	return nil
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
	h := sha256.Sum256([]byte(username + "\x00" + password))
	return hex.EncodeToString(h[:])
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
		// Don't cache failures: legitimate retry after typo should
		// not be locked out by a cached negative.
		return
	}
	k := b.key(username, password)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.entries[k] = bindCacheEntry{
		expiresAt: time.Now().Add(b.ttl),
	}
}
