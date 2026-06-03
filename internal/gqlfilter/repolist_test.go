package gqlfilter

import (
	"encoding/json"
	"strings"
	"testing"
)

// The exact query `gh repo list` (no owner) sends: `viewer` ALIASED as `repositoryOwner`,
// with a repositories connection. This reproduces the reported leak — a deny-default token
// enumerating the custodian's private repos — to find where it slips past the filter.
func TestRepoList_ViewerAlias_Augment(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	q := `query RepositoryList($perPage:Int!,$endCursor:String,$privacy:RepositoryPrivacy,$fork:Boolean) {
		repositoryOwner: viewer {
			login
			repositories(first: $perPage, after: $endCursor, privacy: $privacy, isFork: $fork, ownerAffiliations: OWNER, orderBy: { field: PUSHED_AT, direction: DESC }) {
				nodes{ name nameWithOwner isPrivate description }
				totalCount
				pageInfo{hasNextPage,endCursor}
			}
		}
	}`
	aug, err := s.Augment(q)
	if err != nil {
		t.Fatalf("AUGMENT FAILED (runtime would fail-closed → 403, not leak): %v", err)
	}
	t.Logf("augmented query:\n%s", aug)
	if !strings.Contains(aug, markerAlias) {
		t.Fatalf("NO repo marker injected onto viewer.repositories.nodes — they would NOT be redacted")
	}
}

// gh runs a schema-introspection query before `gh repo list`. Augment must accept it (return
// no error) — otherwise the proxy fails closed and denies it even though the classifier allows
// introspection as "meta".
func TestIntrospection_Augments(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	q := `query Repository_fields{Repository: __type(name: "Repository"){fields(includeDeprecated: true){name}}}`
	aug, err := s.Augment(q)
	if err != nil {
		t.Fatalf("Augment rejected introspection (proxy would fail-closed deny): %v", err)
	}
	if !strings.Contains(aug, "__type") {
		t.Fatalf("augmented introspection lost __type: %s", aug)
	}
}

func TestRepoList_ViewerAlias_FilterRedacts(t *testing.T) {
	resp := `{"data":{"repositoryOwner":{"login":"octocat","repositories":{
		"nodes":[{"name":"private-repo","nameWithOwner":"octocat/private-repo","isPrivate":true,
		          "bghRepoTagZ9":"octocat/private-repo","bghRepoTypeZ9":"Repository"}],
		"totalCount":36}}}}`
	var parsed map[string]any
	if err := json.Unmarshal([]byte(resp), &parsed); err != nil {
		t.Fatal(err)
	}
	out := Filter(parsed, func(owner, repo, resource string, _ bool) bool { return false }) // deny everything
	b, _ := json.Marshal(out)
	t.Logf("filtered response: %s", b)
	if strings.Contains(string(b), "private-repo") {
		t.Fatalf("LEAK: denied repo survived the filter: %s", b)
	}
}
