package main

import (
	"context"
	"sync"
	"time"
)

// identityCacheTTL is the in-process Kratos identity cache window. M1: a
// misbehaving client renewing tokens at high rate (Tailscale, Immich
// mobile reconnects) hammered the Kratos admin API. Caching the identity
// for 30s absorbs the burst.
//
// Trade-off (M5): group changes lag by up to 30s. The Hydra consent
// remember (1h) and refresh window (30d) dominate this lag for already-
// logged-in users; for new flows the lag is bounded.
const identityCacheTTL = 30 * time.Second

// identityCache is a tiny TTL-keyed cache used by handleConsent.
// Goroutine-safe; entries expire lazily on read.
type identityCache struct {
	mu      sync.Mutex
	entries map[string]identityCacheEntry
}

type identityCacheEntry struct {
	identity *Identity
	expires  time.Time
}

func newIdentityCache() *identityCache {
	return &identityCache{entries: map[string]identityCacheEntry{}}
}

func (c *identityCache) get(subject string) (*Identity, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[subject]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expires) {
		delete(c.entries, subject)
		return nil, false
	}
	return e.identity, true
}

func (c *identityCache) put(subject string, id *Identity) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[subject] = identityCacheEntry{
		identity: id,
		expires:  time.Now().Add(identityCacheTTL),
	}
}

// invalidate drops a single subject's entry. Used by /admin/revoke-user
// so a force re-login takes effect immediately rather than waiting out
// the TTL.
func (c *identityCache) invalidate(subject string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, subject)
}

// globalIdentityCache is shared by all consent flows. Initialised at
// process start; the consent service is a single-process container.
var globalIdentityCache = newIdentityCache()

// getIdentityCached wraps cfg.Kratos.GetIdentity with the global TTL
// cache. Cache misses fall through to the admin API call and store the
// result on success. Errors are not cached.
func getIdentityCached(ctx context.Context, cfg Config, subject string) (*Identity, error) {
	if id, ok := globalIdentityCache.get(subject); ok {
		return id, nil
	}
	id, err := cfg.Kratos.GetIdentity(ctx, subject)
	if err != nil {
		return nil, err
	}
	if id != nil {
		globalIdentityCache.put(subject, id)
	}
	return id, nil
}
