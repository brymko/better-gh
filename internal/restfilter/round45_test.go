package restfilter

import "testing"

// TestR45_RulesetHistoryOpaque pins round-45 F6: the org ruleset history-version reads embed opaque numeric
// repo ids inside a freeform `state` object, so they must fail closed (the round-42 F2 sibling the
// declaresOpaqueRepoID guard cannot derive). The repo-scoped /repos twin is gated by its path scope.
func TestR45_RulesetHistoryOpaque(t *testing.T) {
	for _, p := range []string{
		"/orgs/acme/rulesets/5/history",
		"/orgs/acme/rulesets/5/history/9",
	} {
		if !HasOpaqueRepoID(p) {
			t.Errorf("%s should be opaque-repo-id (fail closed) but HasOpaqueRepoID==false", p)
		}
	}
	if HasOpaqueRepoID("/repos/acme/r/rulesets/5/history/9") {
		t.Errorf("the repo-scoped ruleset history is path-gated and must NOT be opaque-repo-id")
	}
}

// TestR45_BodyHasOpaqueRepoIDs pins round-45 F5: a write body naming repos only by numeric
// selected_repository_ids[] is detected (the proxy then fails it closed under a per-repo carve-out).
func TestR45_BodyHasOpaqueRepoIDs(t *testing.T) {
	if !BodyHasOpaqueRepoIDs([]byte(`{"visibility":"selected","selected_repository_ids":[123,456]}`)) {
		t.Error("a selected_repository_ids[] body must be detected")
	}
	if BodyHasOpaqueRepoIDs([]byte(`{"visibility":"all","selected_repository_ids":[]}`)) {
		t.Error("an EMPTY selected_repository_ids[] names no repo and must NOT be flagged")
	}
	if BodyHasOpaqueRepoIDs([]byte(`{"name":"s","repositories":["acme/ok"]}`)) {
		t.Error("a full-name repositories[] body is mapped elsewhere and must NOT be flagged here")
	}
}
