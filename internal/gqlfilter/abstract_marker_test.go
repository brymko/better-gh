package gqlfilter

import (
	"strings"
	"testing"
)

// Round-12 audit H1: a selection written against an interface/union type (e.g. `... on Comment
// { body }`, or a field whose declared type is abstract like `subject: ReferencedSubject`) used
// to receive NO repository marker, because interfaces/unions are never themselves repo-scoped.
// The cross-repo object then streamed to the client untagged. augment now injects a per-member
// marker fragment for every repo-scoped concrete possibility.

func TestAugment_AbstractSelectionGetsMemberMarkers(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"comment-via-search":   `query{search(query:"x",type:ISSUE,first:1){nodes{ ... on Comment { body } }}}`,
		"comment-via-timeline": `query{repository(owner:"o",name:"a"){issue(number:1){timelineItems(first:9){nodes{ ... on ReferencedEvent { subject { ... on Comment { body } } } }}}}}`,
		"node-interface":       `query{node(id:"X"){ ... on Comment { body } }}`,
	}
	for name, q := range cases {
		aug, err := s.Augment(q)
		if err != nil {
			t.Fatalf("[%s] augment must succeed (else it would fail closed, but these are typeable): %v", name, err)
		}
		if !strings.Contains(aug, markerAlias) {
			t.Errorf("[%s] augmented query carries NO repository marker — cross-repo content would leak:\n%s", name, aug)
		}
		// The injected markers must be per-member fragments on concrete repo-scoped types.
		if !strings.Contains(aug, "... on IssueComment") && !strings.Contains(aug, "...on IssueComment") {
			t.Errorf("[%s] expected an injected `... on IssueComment` member marker:\n%s", name, aug)
		}
	}
}

// The filter must redact an abstract-selected object that resolves to a denied repo, finding the
// marker under its per-member suffixed alias.
func TestFilter_RedactsAbstractMemberFromDeniedRepo(t *testing.T) {
	// Shape of a GitHub response to the augmented `... on Comment { body }`: a concrete
	// IssueComment carrying the per-member marker + type marker that augment injects.
	resp := map[string]any{
		"data": map[string]any{
			"node": map[string]any{
				"body":                        "CROSS_REPO_DENIED_SECRET",
				markerAlias + "_IssueComment": map[string]any{"repository": map[string]any{"nameWithOwner": "denied/secret"}},
				markerTypeAlias:               "IssueComment",
			},
		},
	}
	out := Filter(resp, func(owner, repo, resource, _ string) bool {
		return owner+"/"+repo == "allowed/ok" // deny everything except allowed/ok
	})
	node := out["data"].(map[string]any)["node"]
	if node != nil {
		t.Fatalf("denied-repo comment reached via an interface selection was NOT redacted: %#v", node)
	}
}

// Control: the same object in an ALLOWED repo is kept, and the injected markers are stripped.
func TestFilter_KeepsAbstractMemberFromAllowedRepoAndStripsMarkers(t *testing.T) {
	resp := map[string]any{
		"node": map[string]any{
			"body":                        "visible",
			markerAlias + "_IssueComment": map[string]any{"repository": map[string]any{"nameWithOwner": "allowed/ok"}},
			markerTypeAlias:               "IssueComment",
		},
	}
	out := Filter(resp, func(owner, repo, resource, _ string) bool { return owner+"/"+repo == "allowed/ok" })
	node, ok := out["node"].(map[string]any)
	if !ok {
		t.Fatal("allowed-repo comment was wrongly redacted")
	}
	if node["body"] != "visible" {
		t.Fatalf("body lost: %#v", node)
	}
	for k := range node {
		if strings.HasPrefix(k, "bghRepo") {
			t.Errorf("injected marker %q leaked to the client", k)
		}
	}
}
