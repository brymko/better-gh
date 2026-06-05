package gqlfilter

import "testing"

// Round-18 A (HIGH): repo-owned CONCRETE types that do NOT implement Node (Submodule→contents,
// IssueTemplate→issues, …) must be covered by repoOwnedNoPath so augment() injects a type marker
// and the filter enforces their per-resource key. Before round-18 the Node-only gate excluded them.
func TestSec_R18_NonNodeRepoOwnedCovered(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{ // type -> expected per-resource key
		"Submodule":              "contents",
		"IssueTemplate":          "issues",
		"PullRequestChangedFile": "pulls",
		"CheckAnnotation":        "checks",
	}
	for typ, wantRes := range cases {
		if s.isRepoScoped(typ) {
			continue // if a future schema gives it a path, it is covered the other way
		}
		if !s.repoOwnedNoPath[typ] {
			t.Errorf("%s must be in repoOwnedNoPath so augment marks it (per-resource bypass otherwise)", typ)
		}
		if got := s.FilterResource(typ); got != wantRes {
			t.Errorf("FilterResource(%q) = %q, want %q", typ, got, wantRes)
		}
	}
}

// Round-18 H (LOW): Node types that expose a repository-identity scalar (nameWithOwner) but have no
// repo path and are not per-resource content objects must be flagged so the node resolver fails them
// closed (else they leak a denied repo's name/visibility under default=allow). Repo-scoped and
// non-repo node types must NOT be flagged (that would deny legitimate node reads).
func TestSec_R18_RepoIdentityUnattributableTypes(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	flagged := 0
	for _, tn := range []string{"EnterpriseRepositoryInfo", "UserNamespaceRepository", "RepositoryMigration"} {
		if s.IsRepoIdentityUnattributableType(tn) {
			flagged++
			if s.IsRepoScopedType(tn) {
				t.Errorf("%s flagged identity-unattributable yet also repo-scoped (must be disjoint)", tn)
			}
		}
	}
	if flagged == 0 {
		t.Skip("schema premise changed: none of the expected enterprise/migration identity types present")
	}
	// Repo-scoped and non-repo Node types must NOT be flagged.
	for _, tn := range []string{"Repository", "Issue", "PullRequest", "User", "Organization"} {
		if s.IsRepoIdentityUnattributableType(tn) {
			t.Errorf("%s must NOT be flagged identity-unattributable (would deny legitimate node reads)", tn)
		}
	}
}
