package nodecache

import (
	"strconv"
	"testing"
	"time"
)

// The cache must not grow without bound: once at capacity, a new (uncached) id is not
// stored. Already-cached ids remain retrievable; a miss simply re-resolves upstream.
func TestCacheCapBoundsSize(t *testing.T) {
	c := New(time.Hour) // long TTL so nothing expires during the test
	t.Cleanup(c.Stop)

	for i := 0; i < maxEntries; i++ {
		c.Put("id-"+strconv.Itoa(i), "o", "r", "T")
	}
	// At capacity: a brand-new id must be refused (not cached).
	c.Put("overflow-id", "o", "r", "T")
	if _, _, _, ok := c.Get("overflow-id"); ok {
		t.Fatal("cache exceeded its cap: a new id was cached when full")
	}
	// An id inserted before the cap was reached is still present.
	if _, _, _, ok := c.Get("id-0"); !ok {
		t.Fatal("an entry cached before capacity should still be retrievable")
	}
	// Re-Put of an EXISTING id when full must still refresh it (no new key added).
	c.Put("id-0", "o2", "r2", "T")
	if owner, _, _, ok := c.Get("id-0"); !ok || owner != "o2" {
		t.Fatalf("updating an existing entry at capacity should succeed, got owner=%q ok=%v", owner, ok)
	}
}
