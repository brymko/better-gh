package nodecache

import (
	"encoding/json"
	"sync"
	"time"
)

type entry struct {
	Owner     string
	Repo      string
	ExpiresAt time.Time
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

func (c *Cache) Ingest(owner, repo string, responseBody []byte) {
	var parsed any
	if err := json.Unmarshal(responseBody, &parsed); err != nil {
		return
	}

	expires := time.Now().Add(c.ttl)
	c.mu.Lock()
	defer c.mu.Unlock()
	walkIngest(parsed, func(id string) {
		c.entries[id] = entry{Owner: owner, Repo: repo, ExpiresAt: expires}
	})
}

func (c *Cache) Lookup(requestBody []byte) (owner, repo string, ok bool) {
	var parsed any
	if err := json.Unmarshal(requestBody, &parsed); err != nil {
		return "", "", false
	}

	obj, isObj := parsed.(map[string]any)
	if !isObj {
		return "", "", false
	}

	vars, hasVars := obj["variables"]
	if !hasVars {
		return "", "", false
	}

	now := time.Now()
	c.mu.RLock()
	defer c.mu.RUnlock()

	var found string
	walkValues(vars, func(s string) bool {
		if e, exists := c.entries[s]; exists && e.ExpiresAt.After(now) {
			owner = e.Owner
			repo = e.Repo
			found = s
			return true
		}
		return false
	})

	return owner, repo, found != ""
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
				if e.ExpiresAt.Before(now) {
					delete(c.entries, k)
				}
			}
			c.mu.Unlock()
		}
	}
}

func walkIngest(v any, emit func(string)) {
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			if (k == "id" || k == "node_id") {
				if s, ok := child.(string); ok && s != "" {
					emit(s)
				}
			}
			walkIngest(child, emit)
		}
	case []any:
		for _, child := range val {
			walkIngest(child, emit)
		}
	}
}

func walkValues(v any, match func(string) bool) bool {
	switch val := v.(type) {
	case string:
		return match(val)
	case map[string]any:
		for _, child := range val {
			if walkValues(child, match) {
				return true
			}
		}
	case []any:
		for _, child := range val {
			if walkValues(child, match) {
				return true
			}
		}
	}
	return false
}
