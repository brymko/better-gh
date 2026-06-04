package gqlfilter

import (
	"fmt"
	"strings"
	"testing"
)

// Audit F3: a leniently-kept (KeepShell) repository container must expose ONLY its granted
// repo-scoped children, not its own metadata scalars or non-repo-scoped leaf content
// (contributingGuidelines.body), which the direct path denies under base=none.
func TestFilterKeepShellStripsContainerOwnData(t *testing.T) {
	resp := map[string]any{
		"repository": map[string]any{
			markerAlias:     "secret/repo", // Repository container marker = nameWithOwner (string)
			markerTypeAlias: "Repository",
			"description":   "SECRET_DESC",
			"sshUrl":        "git@github.com:secret/repo.git",
			"diskUsage":     float64(123),
			"contributingGuidelines": map[string]any{ // non-repo-scoped leaf content
				"body": "CONTRIB_SECRET",
			},
			"issues": map[string]any{"nodes": []any{
				map[string]any{
					markerAlias:     map[string]any{"repository": map[string]any{"nameWithOwner": "secret/repo"}},
					markerTypeAlias: "Issue",
					"title":         "GRANTED_ISSUE",
				},
			}},
		},
	}
	out := FilterWithDecision(resp, func(owner, repo, resource, typename string) Decision {
		if typename == RepositoryContainerType {
			return KeepShell // readable in some way, but metadata denied
		}
		if resource == "issues" {
			return Keep
		}
		return Deny
	})
	s := fmt.Sprintf("%v", out)
	for _, leak := range []string{"SECRET_DESC", "git@github.com", "CONTRIB_SECRET", "123"} {
		if strings.Contains(s, leak) {
			t.Errorf("F3 leak: container own-data %q survived KeepShell: %s", leak, s)
		}
	}
	if !strings.Contains(s, "GRANTED_ISSUE") {
		t.Errorf("granted issues=read child wrongly stripped: %s", s)
	}
	if strings.Contains(s, markerAlias) || strings.Contains(s, markerTypeAlias) {
		t.Errorf("marker leaked: %s", s)
	}
}

// Audit F5: an output-amplifying query (many abstract selections, each fanned out to every
// repo-scoped concrete member) must fail closed at the augment output cap, not balloon unbounded.
func TestAugmentOutputCapFailsClosed(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("query{")
	for i := 0; i < 1500; i++ {
		fmt.Fprintf(&b, "a%d: node(id:\"PR_x\"){__typename} ", i)
	}
	b.WriteString("}")
	if _, err := s.Augment(b.String()); err == nil {
		t.Fatal("F5: output-amplifying query should fail closed at the augment cap")
	}
	// A normal query still augments fine.
	if _, err := s.Augment(`query{repository(owner:"o",name:"r"){issues(first:1){nodes{title}}}}`); err != nil {
		t.Fatalf("normal query must still augment: %v", err)
	}
}
