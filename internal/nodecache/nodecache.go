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
	expiresAt time.Time
}

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

// Get returns a previously verified node-ID → repo mapping, if present and unexpired.
func (c *Cache) Get(id string) (owner, repo string, ok bool) {
	if id == "" {
		return "", "", false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, exists := c.entries[id]
	if !exists || !e.expiresAt.After(time.Now()) {
		return "", "", false
	}
	return e.owner, e.repo, true
}

// Put records an authoritative node-ID → repo mapping. Callers MUST only pass
// mappings obtained from GitHub, never ones inferred from request/response sniffing.
func (c *Cache) Put(id, owner, repo string) {
	if id == "" || owner == "" || repo == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[id] = entry{owner: owner, repo: repo, expiresAt: time.Now().Add(c.ttl)}
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
