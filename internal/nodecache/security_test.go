package nodecache

// FINDING 2 (CRITICAL): cross-repo node attribution — fixed by design.
//
// The cache no longer learns node-ID → repo mappings by sniffing read responses
// (the old Ingest path, which attributed every node ID in a response to one repo and
// could be poisoned via cross-references or multi-root reads). It now stores only
// authoritative mappings the proxy resolved from GitHub. There is therefore no way to
// inject a mapping without GitHub confirming the node's real repository.
//
// End-to-end proof that a node-ID mutation is authorized against the node's REAL
// repository (and denied when that repo is denied) lives in
// internal/proxy/security_test.go: TestSec_MutationResolvesToRealRepoAndDenies.

import (
	"testing"
	"time"
)

// The store only returns what was explicitly Put (i.e. resolved authoritatively).
func TestSec_OnlyVerifiedMappingsServed(t *testing.T) {
	c := New(30 * time.Minute)
	defer c.Stop()

	if _, _, _, ok := c.Get("PR_kwDONeverResolved"); ok {
		t.Fatal("a node never resolved from GitHub must not be in the cache")
	}

	c.Put("PR_kwDOResolved", "allowed-org", "rw-repo", "PullRequest")
	owner, repo, _, ok := c.Get("PR_kwDOResolved")
	if !ok || owner != "allowed-org" || repo != "rw-repo" {
		t.Fatalf("verified mapping should be served verbatim, got %s/%s ok=%v", owner, repo, ok)
	}
}
