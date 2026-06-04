package gqlfilter

import (
	"strings"
	"testing"
)

// Round-16 HIGH-1: Node OBJECT types that belong to a repository but expose NO field path to it
// (only an argumented connection, or a union whose members are repo-scoped types other than
// Repository) must be recognized as repo-owned-but-unattributable, so the proxy's node resolver can
// fail them closed instead of treating them as constraint-free non-repo nodes (which leaked a denied
// repo's data/identity/oracle via node(id:)).
func TestRepoOwnedUnattributableNodeTypes(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// These genuinely belong to a repo but have no derivable repoPath → must be flagged.
	for _, tn := range []string{
		"Workflow", "DeployKey", "ClosedEvent", "DeploymentReview",
		"RepositoryTopic", "RepositoryCustomProperty",
	} {
		if !s.IsRepoOwnedUnattributableNodeType(tn) {
			t.Errorf("%s must be flagged repo-owned-unattributable (would leak via node(id:))", tn)
		}
		// Must be disjoint from the pathed set (those resolve to a repository normally).
		if s.IsRepoScopedType(tn) {
			t.Errorf("%s is unattributable yet also reported repo-scoped (paths must be disjoint)", tn)
		}
	}
	// Pathed repo types (resolve normally) and non-repo types must NOT be flagged — flagging them
	// would deny legitimate node(id:) reads.
	for _, tn := range []string{
		"Repository", "Issue", "PullRequest", "Commit", "Discussion", // pathed → resolvable
		"User", "Organization", "Bot", "Gist", // non-repo
	} {
		if s.IsRepoOwnedUnattributableNodeType(tn) {
			t.Errorf("%s must NOT be flagged unattributable (would deny legitimate node reads)", tn)
		}
	}
}

// Round-16 HIGH-2: marker injection is bounded DURING construction. A query of thousands of repeated
// abstract selections (each expands to ~130 member fragments) must fail closed via the injection
// budget — before the AST/serialization blowup the old post-serialization output cap allowed.
func TestAugmentInjectionBudgetFailsClosed(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// ~2000 abstract node selections × ~130 repo-scoped Node members each ≫ maxAugmentInjections.
	// Well under the 100k token pre-parse guard, so it would otherwise reach the expensive walk.
	var b strings.Builder
	b.WriteString("query{")
	for i := 0; i < 2000; i++ {
		b.WriteString(`node(id:"x"){__typename}`)
	}
	b.WriteString("}")
	if _, err := s.Augment(b.String()); err == nil {
		t.Fatal("a marker-injection bomb must fail closed (Augment should return an error), got nil")
	}

	// Control: a normal query augments fine and is small.
	out, err := s.Augment(`query{ repository(owner:"o",name:"r"){ pullRequests(first:1){ nodes{ title } } } }`)
	if err != nil {
		t.Fatalf("a normal query must augment without error: %v", err)
	}
	if !strings.Contains(out, markerAlias) {
		t.Fatalf("normal augmented query should carry a repo marker, got: %s", out)
	}
}
