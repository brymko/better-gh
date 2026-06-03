package nodecache

import (
	"testing"
	"time"
)

func TestPutGetRoundTrip(t *testing.T) {
	c := New(30 * time.Minute)
	defer c.Stop()

	c.Put("PR_kwDOabc", "octocat", "hello-world", "PullRequest")
	owner, repo, _, ok := c.Get("PR_kwDOabc")
	if !ok {
		t.Fatal("expected hit")
	}
	if owner != "octocat" || repo != "hello-world" {
		t.Fatalf("got %s/%s", owner, repo)
	}
}

func TestGetMiss(t *testing.T) {
	c := New(30 * time.Minute)
	defer c.Stop()

	if _, _, _, ok := c.Get("PR_never"); ok {
		t.Fatal("expected miss")
	}
	if _, _, _, ok := c.Get(""); ok {
		t.Fatal("empty id must miss")
	}
}

func TestPutRejectsIncomplete(t *testing.T) {
	c := New(30 * time.Minute)
	defer c.Stop()

	c.Put("", "o", "r", "T")
	c.Put("PR_x", "", "r", "T")
	c.Put("PR_y", "o", "", "T")
	c.mu.RLock()
	n := len(c.entries)
	c.mu.RUnlock()
	if n != 0 {
		t.Fatalf("incomplete mappings must be rejected, got %d entries", n)
	}
}

func TestTTLExpiration(t *testing.T) {
	c := New(10 * time.Millisecond)
	defer c.Stop()

	c.Put("PR_kwDOttl", "o", "r", "T")
	if _, _, _, ok := c.Get("PR_kwDOttl"); !ok {
		t.Fatal("expected hit before expiry")
	}
	time.Sleep(20 * time.Millisecond)
	if _, _, _, ok := c.Get("PR_kwDOttl"); ok {
		t.Fatal("expected miss after TTL expiry")
	}
}

func TestPutOverwrites(t *testing.T) {
	c := New(30 * time.Minute)
	defer c.Stop()

	c.Put("PR_x", "old-org", "old-repo", "T")
	c.Put("PR_x", "new-org", "new-repo", "T")
	owner, repo, _, _ := c.Get("PR_x")
	if owner != "new-org" || repo != "new-repo" {
		t.Fatalf("expected latest authoritative mapping, got %s/%s", owner, repo)
	}
}
