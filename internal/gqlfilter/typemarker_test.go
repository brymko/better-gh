package gqlfilter

import (
	"strings"
	"testing"

	"github.com/vektah/gqlparser/v2"
)

// The augmented query must (a) carry the type marker on repo-scoped selections and (b)
// remain VALID against the schema — GitHub executes it verbatim, so an invalid injection
// would break every read.
func TestAugment_InjectsValidTypeMarker(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	queries := []string{
		`query{repository(owner:"o",name:"r"){name pullRequests(first:1){nodes{title}}}}`,
		`query{repository(owner:"o",name:"r"){owner{repository(name:"r"){pullRequests(first:1){nodes{title}} issues(first:1){nodes{title}}}}}}`,
		`query{search(query:"x",type:ISSUE,first:5){nodes{... on Issue{title} ... on PullRequest{title}}}}`,
		`query{node(id:"X"){... on Repository{name} ... on PullRequest{title}}}`,
		`query{viewer{repositories(first:5){nodes{name pullRequests(first:1){nodes{title}}}}}}`,
	}
	for _, q := range queries {
		aug, err := s.Augment(q)
		if err != nil {
			t.Fatalf("augment failed for %q: %v", q, err)
		}
		if !strings.Contains(aug, markerTypeAlias) || !strings.Contains(aug, "__typename") {
			t.Fatalf("type marker not injected for %q:\n%s", q, aug)
		}
		// The injected output must re-validate — GitHub runs this exact document.
		if _, gerr := gqlparser.LoadQuery(s.schema, aug); gerr != nil {
			t.Fatalf("augmented query is INVALID for %q: %s\n%s", q, gerr.Error(), aug)
		}
	}
}

// The type marker maps the runtime __typename to the same per-resource keys the policy uses.
func TestTypeResourceMapping(t *testing.T) {
	cases := map[string]string{
		"PullRequest": "pulls", "PullRequestReview": "pulls",
		"Issue": "issues", "IssueComment": "issues",
		"Commit": "commits", "Release": "releases", "Ref": "branches",
		"CheckRun": "checks", "Blob": "contents",
		"Repository": "metadata", "Discussion": "metadata", "": "metadata", "SomethingNew": "metadata",
	}
	for typename, want := range cases {
		if got := typeResource(typename); got != want {
			t.Errorf("typeResource(%q) = %q, want %q", typename, got, want)
		}
	}
}

// The filter redacts per-resource using the type marker: a PullRequest (resource "pulls")
// is redacted when pulls is denied, an Issue (resource "issues") kept when allowed, and the
// repository container (resource "metadata") kept so its allowed children survive.
func TestFilter_RedactsByResource(t *testing.T) {
	resp := map[string]any{"data": map[string]any{
		"repository": map[string]any{
			markerAlias: "o/r", markerTypeAlias: "Repository",
			"pullRequests": map[string]any{"nodes": []any{
				map[string]any{markerAlias: map[string]any{"nameWithOwner": "o/r"}, markerTypeAlias: "PullRequest", "title": "PR_SECRET"},
			}},
			"issues": map[string]any{"nodes": []any{
				map[string]any{markerAlias: map[string]any{"nameWithOwner": "o/r"}, markerTypeAlias: "Issue", "title": "ISSUE_OK"},
			}},
		},
	}}
	// Authorize: metadata + issues allowed, pulls denied (the pulls="none" semantics).
	authorized := func(owner, repo, resource string, _ bool) bool {
		return resource == "metadata" || resource == "issues"
	}
	out := Filter(resp, authorized)
	js := mustJSON(out)
	if strings.Contains(js, "PR_SECRET") {
		t.Fatalf("pulls object not redacted by resource: %s", js)
	}
	if !strings.Contains(js, "ISSUE_OK") {
		t.Fatalf("issues object wrongly redacted: %s", js)
	}
	if strings.Contains(js, markerAlias) || strings.Contains(js, markerTypeAlias) {
		t.Fatalf("markers not stripped: %s", js)
	}
}

// A client that pre-declares the reserved TYPE alias must be rejected (else it could
// suppress the resource tag and defeat per-resource redaction).
func TestAugment_RejectsReservedTypeAlias(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	q := `query{repository(owner:"o",name:"r"){` + markerTypeAlias + `:name}}`
	if _, err := s.Augment(q); err == nil {
		t.Fatalf("Augment must reject a query using the reserved type alias %q", markerTypeAlias)
	}
}
