package gqlfilter

import (
	"testing"

	"github.com/vektah/gqlparser/v2/ast"
)

// round-15 HIGH: the response filter's type→resource map must be derived from the schema's
// @docsCategory, not a ~30-entry hand map that silently mapped repo-scoped types with a real
// per-resource category (Environment→deployments, WorkflowRun→actions, Milestone/Label→issues,
// PullRequestThread→pulls, branchProtectionRules→branches, …) to "metadata" (base access).
func TestR15_FilterResourceFromDocsCategory(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"Environment":          "deployments",
		"WorkflowRun":          "actions",
		"Milestone":            "issues",
		"Label":                "issues",
		"BranchProtectionRule": "branches",
		"PullRequestThread":    "pulls",
		"PullRequest":          "pulls",
		"Issue":                "issues",
		"Release":              "releases",
		"Blob":                 "contents", // docsCategory "git" → contents
		"Ref":                  "branches", // override (docsCategory "git")
		"Status":               "checks",   // override (docsCategory "commits")
		"Repository":           "metadata", // category "repos" has no per-resource key
	}
	for typ, want := range cases {
		if got := s.FilterResource(typ); got != want {
			t.Errorf("FilterResource(%s)=%q, want %q", typ, got, want)
		}
	}
}

// Build-time invariant: every repo-scoped OBJECT type whose @docsCategory is a real per-resource key
// MUST map to that resource (never silently "metadata"), preventing the round-15 fail-open. Mirrors TestSchemaCoverageInvariant for the marker machinery.
func TestR15_TypeResourceCoverageInvariant(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for name := range s.repoScoped {
		def := s.schema.Types[name]
		if def == nil || def.Kind != ast.Object {
			continue
		}
		d := def.Directives.ForName("docsCategory")
		if d == nil {
			continue
		}
		arg := d.Arguments.ForName("name")
		if arg == nil || arg.Value == nil {
			continue
		}
		// expected = the explicit override if any, else the docsCategory-derived key.
		want := typeResourceOverride[name]
		if want == "" {
			want = docsCategoryResource[arg.Value.Raw]
		}
		if want == "" {
			continue // category has no per-resource key → "metadata" is correct
		}
		if got := s.FilterResource(name); got != want {
			t.Errorf("repo-scoped %s @docsCategory=%q must map to %q, got %q (silent per-resource fail-open)",
				name, arg.Value.Raw, want, got)
		}
	}
}

// The node resolver relies on IsKnownNodeObjectType to fail closed on unknown types; sanity-check the set.
func TestR15_KnownNodeObjectTypes(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, known := range []string{"PullRequest", "Issue", "Repository", "User", "Organization"} {
		if !s.IsKnownNodeObjectType(known) {
			t.Errorf("%s should be a known Node object type", known)
		}
	}
	if s.IsKnownNodeObjectType("UnknownRepoScopedType") {
		t.Error("an unknown type must NOT be a known Node object type")
	}
}
