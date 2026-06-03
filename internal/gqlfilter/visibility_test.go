package gqlfilter

import (
	"encoding/json"
	"strings"
	"testing"
)

// Augment must inject the visibility marker (isPrivate, aliased bghRepoVisZ9) onto every
// repo-scoped selection, so the response filter can apply the public-repo baseline against
// GitHub's REAL visibility rather than a value the client could control.
func TestAugment_InjectsVisibilityMarker(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`query{repository(owner:"o",name:"r"){name}}`,                                // Repository → isPrivate
		`query{repository(owner:"o",name:"r"){pullRequests(first:1){nodes{title}}}}`, // PullRequest → repository{isPrivate}
	} {
		aug, err := s.Augment(q)
		if err != nil {
			t.Fatalf("augment failed for %q: %v", q, err)
		}
		if !strings.Contains(aug, markerVisAlias) {
			t.Fatalf("no visibility marker injected for %q:\n%s", q, aug)
		}
		if !strings.Contains(aug, "isPrivate") {
			t.Fatalf("visibility marker does not read isPrivate for %q:\n%s", q, aug)
		}
	}
}

// A client cannot pre-declare the visibility marker alias to forge a "public" verdict: Augment
// must fail closed (the proxy then denies the whole request) just as it does for the other
// reserved markers.
func TestAugment_RejectsClientVisibilityAlias(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	q := `query{repository(owner:"o",name:"r"){bghRepoVisZ9: isPrivate name}}`
	if _, err := s.Augment(q); err == nil {
		t.Fatal("Augment accepted a client-declared visibility marker alias (would let a client forge visibility)")
	}
}

// The filter applies the public-repo baseline using ONLY the injected visibility marker: a
// public repo (isPrivate=false) is kept by a baseline-style callback, a private repo
// (isPrivate=true) is redacted, and a repo whose visibility is ABSENT is treated as private
// and redacted (fail closed). The markers are stripped from the output.
func TestFilter_PublicBaselineUsesRealVisibility(t *testing.T) {
	// Mimics the proxy's public-baseline callback: the explicit policy denies everything, so a
	// repo is kept ONLY if the marker says it is public.
	publicBaseline := func(_, _, _ string, isPrivate bool) bool { return !isPrivate }

	repoObj := func(vis any, name string) map[string]any {
		m := map[string]any{
			markerAlias:     name, // Repository marker is a bare "owner/repo" string
			markerTypeAlias: "Repository",
			"name":          name,
		}
		if vis != nil {
			m[markerVisAlias] = vis
		}
		return m
	}

	resp := map[string]any{"data": map[string]any{"nodes": []any{
		repoObj(false, "o/public-keep"), // public → kept by the baseline
		repoObj(true, "o/private-drop"), // private → redacted
		repoObj(nil, "o/unknown-drop"),  // visibility absent → treated as private → redacted
	}}}

	out := Filter(resp, publicBaseline)
	b, _ := json.Marshal(out)
	js := string(b)
	t.Logf("filtered: %s", js)

	if !strings.Contains(js, "public-keep") {
		t.Fatalf("public repo was dropped by the baseline: %s", js)
	}
	if strings.Contains(js, "private-drop") {
		t.Fatalf("LEAK: private repo survived the public baseline: %s", js)
	}
	if strings.Contains(js, "unknown-drop") {
		t.Fatalf("LEAK: repo with unknown visibility survived (must fail closed): %s", js)
	}
	if strings.Contains(js, markerVisAlias) {
		t.Fatalf("visibility marker not stripped from output: %s", js)
	}
}

// findIsPrivate must locate the boolean through the nested object a non-Repository marker
// produces (e.g. PullRequest's repository{isPrivate}), and report unknown for a null link.
func TestFindIsPrivate_NestedAndNull(t *testing.T) {
	cases := []struct {
		val    any
		isPriv bool
		found  bool
	}{
		{false, false, true},
		{true, true, true},
		{map[string]any{"isPrivate": false}, false, true},                             // PullRequest-style
		{map[string]any{"repository": map[string]any{"isPrivate": true}}, true, true}, // deeper
		{map[string]any{"repository": nil}, false, false},                             // null link → unknown
		{nil, false, false},
	}
	for i, c := range cases {
		priv, found := findIsPrivate(c.val)
		if priv != c.isPriv || found != c.found {
			t.Fatalf("case %d: findIsPrivate(%v) = (%v,%v), want (%v,%v)", i, c.val, priv, found, c.isPriv, c.found)
		}
	}
}
