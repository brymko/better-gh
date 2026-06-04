package gqlfilter

import (
	"strings"
	"testing"
	"time"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

// Regression for round-17 (HIGH): a repoOwnedNoPath content type reached by NAVIGATION (here
// DeploymentReview, @docsCategory "deployments") must be tagged by augment with a TYPE marker even
// though it has no repository path — so the response filter can attribute it to its ancestor's repo
// and enforce deployments="none". Before the fix it received NO marker and leaked unredacted.
//
// The check isolates the fix: BEFORE it, a type marker (bghRepoTypeZ9) is injected ONLY alongside a
// repo marker (on repo-scoped types/members), so NO selection set has a type marker without a repo
// marker. The fix injects exactly that — a type-only marker on the DeploymentReview selection.
func TestR17_AugmentTagsRepoOwnedNoPathByType(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if s.isRepoScoped("DeploymentReview") || !s.repoOwnedNoPath["DeploymentReview"] {
		t.Skipf("schema premise changed: DeploymentReview repoScoped=%v repoOwnedNoPath=%v",
			s.isRepoScoped("DeploymentReview"), s.repoOwnedNoPath["DeploymentReview"])
	}

	q := `query{repository(owner:"o",name:"r"){object(expression:"HEAD"){... on Commit{checkSuites(first:1){nodes{workflowRun{deploymentReviews(first:5){nodes{comment databaseId}}}}}}}}}`
	aug, err := s.Augment(q)
	if err != nil {
		t.Fatalf("augment failed (path must be schema-valid): %v", err)
	}
	doc, perr := parser.ParseQuery(&ast.Source{Input: aug})
	if perr != nil {
		t.Fatalf("re-parsing augmented query: %v", perr)
	}

	var typeOnly func(sels ast.SelectionSet) bool
	typeOnly = func(sels ast.SelectionSet) bool {
		hasType, hasRepo := false, false
		for _, sel := range sels {
			switch f := sel.(type) {
			case *ast.Field:
				if f.Alias == markerTypeAlias {
					hasType = true
				}
				if f.Alias == markerAlias || strings.HasPrefix(f.Alias, markerAlias+"_") {
					hasRepo = true
				}
				if typeOnly(f.SelectionSet) {
					return true
				}
			case *ast.InlineFragment:
				if typeOnly(f.SelectionSet) {
					return true
				}
			}
		}
		return hasType && !hasRepo
	}
	found := false
	for _, op := range doc.Operations {
		if typeOnly(op.SelectionSet) {
			found = true
		}
	}
	if !found {
		t.Fatal("augment injected no type-only marker on a repoOwnedNoPath selection — the round-17 fix is inactive")
	}
}

// Regression for round-17 (HIGH DoS): Augment must NOT run the O(n^2) OverlappingFieldsCanBeMerged
// validation rule. That rule compares every pair of fields sharing a response name within a
// selection set (recursing into their sub-selections, no field-pair memoization), so a ~100KB query
// of same-aliased siblings — under the token cap — drove gqlparser.LoadQuery to multiple seconds of
// CPU on the request path BEFORE the policy deny, a single-token CPU-exhaustion DoS.
func TestR17_AugmentDropsOverlapRule(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	// The quadratic rule must be absent from Augment's active validation set.
	if _, present := s.validationRules.GetInner()["OverlappingFieldsCanBeMerged"]; present {
		t.Fatal("OverlappingFieldsCanBeMerged must be removed from Augment's validation rules")
	}

	// A merge-CONFLICTING query (alias x bound to two different fields) would be REJECTED by the
	// overlap rule; with it removed Augment accepts it (GitHub re-validates upstream and returns an
	// error the response filter handles). This proves the rule is not running.
	if _, err := s.Augment(`query{repository(owner:"o",name:"r"){ x:name x:createdAt }}`); err != nil {
		t.Fatalf("merge-conflicting query should augment (overlap rule removed), got: %v", err)
	}

	// Other validation still runs: an unknown field must still fail closed.
	if _, err := s.Augment(`query{repository(owner:"o",name:"r"){ noSuchFieldXYZ }}`); err == nil {
		t.Fatal("an unknown field must still be rejected by the remaining validation rules")
	}

	// Bound check: the DoS payload (thousands of same-response-name siblings) must augment fast.
	// WITH the quadratic rule this is ~7-11s; without it, well under a second. The generous 4s
	// threshold catches a regression re-introducing the rule without being flaky.
	var b strings.Builder
	b.WriteString(`query{repository(owner:"o",name:"r"){`)
	for i := 0; i < 4000; i++ {
		b.WriteString(" x:owner{login avatarUrl id}")
	}
	b.WriteString("}}")
	start := time.Now()
	if _, err := s.Augment(b.String()); err != nil {
		t.Fatalf("large same-alias sibling query should augment without error: %v", err)
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("Augment of a 4000-sibling query took %v (>4s) — the O(n^2) overlap rule may be back", d)
	}
}
