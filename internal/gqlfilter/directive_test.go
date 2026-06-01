package gqlfilter

import (
	"strings"
	"testing"

	"github.com/vektah/gqlparser/v2"
)

// The formatter must preserve variable definitions, directives, and @skip/@include when
// re-serializing the augmented query — GitHub runs the output verbatim, so a dropped
// variable definition or directive would break the query or change which fields execute.
func TestAugment_PreservesDirectivesAndVariables(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	q := `query Q($n: Int!, $skip: Boolean!, $id: ID!) {
		repository(owner: "o", name: "r") {
			pullRequests(first: $n) @include(if: $skip) { nodes { title @skip(if: $skip) } }
			node1: pullRequest(number: 1) { title }
		}
		node(id: $id) { ... on Issue { title } }
	}`
	aug, err := s.Augment(q)
	if err != nil {
		t.Fatalf("augment failed: %v", err)
	}
	t.Logf("augmented:\n%s", aug)

	for _, must := range []string{
		"$n: Int!", "$skip: Boolean!", "$id: ID!", // variable definitions preserved
		"@include(if: $skip)", "@skip(if: $skip)", // directives preserved
		"first: $n",     // variable usage preserved
		markerAlias,     // repo marker injected
		markerTypeAlias, // type marker injected
		"__typename",    // type marker is __typename
	} {
		if !strings.Contains(aug, must) {
			t.Errorf("augmented query missing %q:\n%s", must, aug)
		}
	}

	// And it must still validate against the schema (GitHub runs it verbatim).
	if _, gerr := gqlparser.LoadQuery(s.schema, aug); gerr != nil {
		t.Fatalf("augmented query invalid: %s", gerr.Error())
	}
}

// A repo-scoped field guarded by @skip/@include must still carry the marker as a sibling so
// that when the object IS present, it is tagged (the directive controls the client's field,
// not our injected marker).
func TestAugment_MarkerNotSuppressibleByDirective(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	q := `query { repository(owner:"o", name:"r") @include(if: true) { name } }`
	aug, err := s.Augment(q)
	if err != nil {
		t.Fatalf("augment failed: %v", err)
	}
	// The marker rides on the repository selection set; the @include on repository governs
	// the whole object (data + marker travel together), which is the safe behaviour.
	if !strings.Contains(aug, markerAlias) || !strings.Contains(aug, markerTypeAlias) {
		t.Errorf("markers not injected into directive-guarded selection:\n%s", aug)
	}
}
