package classifier

import (
	"encoding/base64"
	"testing"
)

// TestR19_ShortLegacyNodeIDCollected pins round-19 F5: a short legacy node ID (base64 of
// "NN:TypeName<smallID>", under 16 chars) must be collected for authoritative resolution, while
// ordinary 8+char identifiers must NOT be (no wasteful resolve on normal reads).
func TestR19_ShortLegacyNodeIDCollected(t *testing.T) {
	collected := map[string]bool{
		base64.StdEncoding.EncodeToString([]byte("05:Issue1")): true, // 12 chars, the documented gap
		base64.StdEncoding.EncodeToString([]byte("03:Ref1")):   true,
		base64.StdEncoding.EncodeToString([]byte("05:Label9")): true,
		"MDU6SXNzdWUx":  true, // == base64("05:Issue1")
		"PR_kwDOABCDEF": true, // modern shape (underscore)
	}
	for id, want := range collected {
		if got := looksLikeNodeID(id); got != want {
			t.Errorf("looksLikeNodeID(%q)=%v, want %v (short/modern node ID must be collected)", id, got, want)
		}
	}
	// Ordinary identifiers that happen to be valid base64 must NOT be collected (else every read
	// targeting an 8+char owner login triggers a wasteful upstream resolve).
	notCollected := []string{"facebook", "kubernetes", "react", "main", "feature1", "octocat"}
	for _, s := range notCollected {
		if looksLikeShortLegacyNodeID(s) {
			t.Errorf("looksLikeShortLegacyNodeID(%q)=true; ordinary identifier must not be a node-ID candidate", s)
		}
	}
}

// TestR19_ShortLegacyNodeIDInMutation proves the end-to-end classifier effect: a mutation whose
// only real target is a SHORT legacy node ID is now collected into NodeIDs (so the proxy resolves
// and policy-checks it), instead of being silently dropped behind an allowed carrier.
func TestR19_ShortLegacyNodeIDInMutation(t *testing.T) {
	shortID := base64.StdEncoding.EncodeToString([]byte("05:Issue1")) // denied object, short legacy ID
	body := []byte(`{"query":"mutation{ closeIssue(input:{issueId:\"` + shortID + `\"}){clientMutationId} carrier: addStar(input:{starrableId:\"R_kgDOABCDEF\"}){clientMutationId} }"}`)
	res := Classify("POST", "/graphql", body)
	found := false
	for _, id := range res.NodeIDs {
		if id == shortID {
			found = true
		}
	}
	if !found {
		t.Errorf("short legacy node ID %q was not collected into NodeIDs %v (carrier-smuggling gap)", shortID, res.NodeIDs)
	}
}

// TestR19_AgentsRepoScoped pins round-19 F6: the Copilot coding-agent endpoints embed the repo at
// /agents/repos/{owner}/{repo}/... and must classify to that repo (not an empty, default-allow scope).
func TestR19_AgentsRepoScoped(t *testing.T) {
	cases := []struct{ method, path, owner, repo string }{
		{"GET", "/api/v3/agents/repos/acme/secret/tasks", "acme", "secret"},
		{"GET", "/agents/repos/acme/secret/tasks/42", "acme", "secret"},
		{"POST", "/api/v3/agents/repos/acme/secret/tasks", "acme", "secret"},
	}
	for _, c := range cases {
		res := Classify(c.method, c.path, nil)
		if res.Owner != c.owner || res.Repo != c.repo {
			t.Errorf("Classify(%s %s) scoped to owner=%q repo=%q, want %q/%q (empty scope = default-allow leak)",
				c.method, c.path, res.Owner, res.Repo, c.owner, c.repo)
		}
		if !res.HasRepo() {
			t.Errorf("Classify(%s %s) HasRepo()=false; agent endpoint must be repo-scoped", c.method, c.path)
		}
	}
}
