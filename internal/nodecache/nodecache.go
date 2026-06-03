// Package nodecache stores authoritative GraphQL node-ID → repository mappings.
//
// Mappings are produced only by resolving a node ID against GitHub (see the proxy's
// resolver) — never by sniffing read responses. This is the trust boundary for
// node-ID-scoped mutations: a write is authorized against the repository GitHub says
// the node belongs to, not one guessed from an earlier read.
package nodecache

import (
	"sync"
	"time"
)

type entry struct {
	owner     string
	repo      string
	typename  string // resolved GraphQL __typename, so per-resource policy is type-derived on cache hits too
	expiresAt time.Time
}

// maxEntries caps the cache so a client reading many distinct node IDs cannot grow it
// without bound (each entry is a verified repo mapping held for the TTL). At capacity, new
// mappings are simply not cached — a miss just re-resolves against GitHub, so correctness is
// unaffected; the periodic evictLoop and TTL free space as entries expire. Only verified
// repo nodes are ever stored (invalid/fake IDs resolve to null and are never Put), so this
// cannot be filled with junk.
const maxEntries = 100_000

type Cache struct {
	mu      sync.RWMutex
	entries map[string]entry
	ttl     time.Duration
	stopCh  chan struct{}
}

func New(ttl time.Duration) *Cache {
	c := &Cache{
		entries: make(map[string]entry),
		ttl:     ttl,
		stopCh:  make(chan struct{}),
	}
	go c.evictLoop()
	return c
}

func (c *Cache) Stop() {
	close(c.stopCh)
}

// Get returns a previously verified node-ID → (repo, __typename) mapping, if present and
// unexpired. The typename lets the caller derive per-resource policy from the node's real
// type on a cache hit, exactly as it would on a fresh resolve.
func (c *Cache) Get(id string) (owner, repo, typename string, ok bool) {
	if id == "" {
		return "", "", "", false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, exists := c.entries[id]
	if !exists || !e.expiresAt.After(time.Now()) {
		return "", "", "", false
	}
	return e.owner, e.repo, e.typename, true
}

// Put records an authoritative node-ID → (repo, __typename) mapping. Callers MUST only pass
// mappings obtained from GitHub, never ones inferred from request/response sniffing.
func (c *Cache) Put(id, owner, repo, typename string) {
	if id == "" || owner == "" || repo == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[id]; !exists && len(c.entries) >= maxEntries {
		return // at capacity; a miss re-resolves, and evictLoop/TTL will free space
	}
	c.entries[id] = entry{owner: owner, repo: repo, typename: typename, expiresAt: time.Now().Add(c.ttl)}
}

func (c *Cache) evictLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case now := <-ticker.C:
			c.mu.Lock()
			for k, e := range c.entries {
				if e.expiresAt.Before(now) {
					delete(c.entries, k)
				}
			}
			c.mu.Unlock()
		}
	}
}
