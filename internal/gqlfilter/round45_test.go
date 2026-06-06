package gqlfilter

import (
	"strings"
	"testing"
)

// TestR45_RecentProjectsNotOwnContent pins round-45 F2: recentProjects is CROSS-OWNER ("projects modified in
// the context of the owner"), so it must NOT be an own-content field — otherwise the user-owned sentinel
// keeps a foreign org's private board past that org's projects="none".
func TestR45_RecentProjectsNotOwnContent(t *testing.T) {
	if userOwnContentFields["recentProjects"] {
		t.Fatal("recentProjects must NOT be in userOwnContentFields (it returns cross-owner boards)")
	}
	// marked as a NON-own-content private field → no sentinel → its self-marked ProjectV2 fails closed.
	body := map[string]any{
		userMarkerAlias:                "octocat",
		ownerMemberMarkerPrefix + "rp": "ProjectV2Connection",
		"rp": map[string]any{"nodes": []any{map[string]any{
			ownerSelfMarkerPrefix + resourceCode("projects"): "ProjectV2",
			"title": "FOREIGN_ORG_BOARD", "id": "p1",
		}}},
	}
	if js := mustJSON(RedactDeniedOwnerPrivate(body, func(string, string) bool { return false }, noUserFieldDenied)); strings.Contains(js, "FOREIGN_ORG_BOARD") {
		t.Fatalf("F2: recentProjects cross-owner board not fail-closed: %s", js)
	}
	// and the augmenter routes it to ownerMemberMarkerPrefix (no sentinel), not userOwnContentMarkerPrefix.
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Augment(`{ viewer { recentProjects(first:1){ nodes { title } } } }`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, userOwnContentMarkerPrefix) {
		t.Fatalf("F2: viewer.recentProjects wrongly own-content-marked (would carry the sentinel):\n%s", out)
	}
}

// TestR45_CommitCommentResource pins round-45 F7: a CommitComment is gated as the "comments" resource (REST
// parity), not "commits" — so a commits=rw, comments=none token cannot react to a commit comment over GraphQL.
func TestR45_CommitCommentResource(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := s.ResourceForType("CommitComment"); got != "comments" {
		t.Fatalf("F7: CommitComment resource = %q, want \"comments\"", got)
	}
}

// TestR45_InlineFragmentBudget pins round-45 F3: inline fragments now count against the spread budget, so a
// query that packs many inline fragments (the PossibleFragmentSpreads quadratic-DoS shape) is rejected before
// the validator Walk instead of driving 35-40s of CPU.
func TestR45_InlineFragmentBudget(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	sb.WriteString(`{ node(id:"x"){ `)
	for i := 0; i < maxAugmentSpreadEdges+100; i++ { // exceeds the budget ONLY because inline frags now count
		sb.WriteString(`...on Repository{__typename} `)
	}
	sb.WriteString(`} }`)
	if _, err := s.Augment(sb.String()); err == nil {
		t.Fatal("F3: a query exceeding the inline-fragment spread budget must be rejected, not walked")
	}
}
