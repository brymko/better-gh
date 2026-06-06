package gqlfilter

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestR22_FragmentGraphDoSBounded pins the round-22 fix: a document of thousands of mutually-referencing
// fragments (which made the validator's per-root Walk burn tens of seconds) is rejected in milliseconds by
// the pre-validation fragment-graph budget, while a normal multi-fragment query still augments.
func TestR22_FragmentGraphDoSBounded(t *testing.T) {
	s, _ := Load()
	const N, fan = 1500, 15
	var b strings.Builder
	b.WriteString(`query{repository(owner:"o",name:"r"){`)
	for i := 0; i < N; i++ {
		fmt.Fprintf(&b, " ...F%d", i)
	}
	b.WriteString("}}")
	for i := 0; i < N; i++ {
		fmt.Fprintf(&b, " fragment F%d on Repository{ name", i)
		for j := 1; j <= fan; j++ {
			fmt.Fprintf(&b, " ...F%d", (i+j)%N)
		}
		b.WriteString(" }")
	}
	start := time.Now()
	if _, err := s.Augment(b.String()); err == nil {
		t.Fatal("a pathological fragment graph must fail closed")
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("fragment-graph DoS not bounded: Augment took %v", d)
	}

	out, err := s.Augment(`query{ repository(owner:"o",name:"r"){ ...rf issues(first:5){ nodes{ ...inf } } } }
		fragment rf on Repository { name nameWithOwner } fragment inf on Issue { title author{ login } }`)
	if err != nil || out == "" {
		t.Fatalf("a legitimate multi-fragment query must still augment, got err=%v", err)
	}
}

// TestR22_CrossReferencedEventURIScrub pins the round-22 fix: a CrossReferencedEvent kept by ambient
// attribution under an allowed issue must have its url/resourcePath URI scalars nulled when they name a
// DENIED foreign repo (an identity/existence oracle the source-content redaction does not cover), while a
// same-repo cross-reference keeps them.
func TestR22_CrossReferencedEventURIScrub(t *testing.T) {
	authorize := func(owner, repo, _, _ string) Decision {
		if owner+"/"+repo == "victim/secret" {
			return Deny
		}
		return Keep
	}
	event := func(url, rp, srcRepo string) map[string]any {
		return map[string]any{
			markerTypeAlias:     "CrossReferencedEvent",
			"isCrossRepository": true,
			"url":               url,
			"resourcePath":      rp,
			"source": map[string]any{
				markerAlias:     map[string]any{"nameWithOwner": srcRepo},
				markerTypeAlias: "Issue",
				"title":         "SECRET-TITLE",
			},
		}
	}
	build := func(ev map[string]any) map[string]any {
		return map[string]any{
			markerAlias:     "allowed/repo",
			markerTypeAlias: RepositoryContainerType,
			"issue": map[string]any{
				markerAlias:     map[string]any{"nameWithOwner": "allowed/repo"},
				markerTypeAlias: "Issue",
				"timelineItems": map[string]any{
					"nodes": []any{ev},
				},
			},
		}
	}

	// Denied foreign cross-reference: url/resourcePath naming victim/secret must be gone.
	denied := FilterWithDecision(build(event(
		"https://github.com/victim/secret/issues/5", "/victim/secret/issues/5", "victim/secret")), authorize)
	if s := fmt.Sprintf("%v", denied); strings.Contains(s, "victim/secret") || strings.Contains(s, "SECRET-TITLE") {
		t.Fatalf("denied cross-repo event leaked foreign repo identity: %s", s)
	}

	// Same-repo cross-reference: url/resourcePath naming the allowed repo must survive.
	same := FilterWithDecision(build(event(
		"https://github.com/allowed/repo/issues/9", "/allowed/repo/issues/9", "allowed/repo")), authorize)
	if s := fmt.Sprintf("%v", same); !strings.Contains(s, "allowed/repo/issues/9") {
		t.Fatalf("same-repo cross-reference url wrongly scrubbed: %s", s)
	}
}

// TestR22_CrossRepoURIScrubCoverage is the drift guard: crossRepoURIScrubTypes must equal the schema-
// derived set of repoOwnedNoPath types exposing BOTH isCrossRepository AND a url/resourcePath scalar, so a
// schema refresh that adds another such cross-repository event type cannot silently leak its foreign URL.
func TestR22_CrossRepoURIScrubCoverage(t *testing.T) {
	s, _ := Load()
	want := map[string]bool{}
	for typ := range s.repoOwnedNoPath {
		def := s.schema.Types[typ]
		if def == nil {
			continue
		}
		hasCross, hasURI := false, false
		for _, f := range def.Fields {
			switch f.Name {
			case "isCrossRepository":
				hasCross = true
			case "url", "resourcePath":
				hasURI = true
			}
		}
		if hasCross && hasURI {
			want[typ] = true
		}
	}
	if !reflect.DeepEqual(want, crossRepoURIScrubTypes) {
		t.Fatalf("crossRepoURIScrubTypes drift: schema-derived=%v static=%v — a new cross-repo URI event "+
			"type is unguarded; add it (and verify scrubCrossRepoURIScalars handles its URL shape)", want, crossRepoURIScrubTypes)
	}
}

// TestR22_RepoFromIssueOrPullRef checks the URL/path parser the cross-repo scrub relies on, including the
// fail-closed behaviour on non-repo paths (so /orgs/... never mis-parses to an owner/repo).
func TestR22_RepoFromIssueOrPullRef(t *testing.T) {
	cases := []struct {
		in, owner, repo string
		ok              bool
	}{
		{"https://github.com/o/r/issues/5", "o", "r", true},
		{"https://github.com/o/r/pull/5", "o", "r", true},
		{"/o/r/issues/5", "o", "r", true},
		{"/o/r/discussions/2", "o", "r", true},
		{"/orgs/acme/teams/x", "", "", false},
		{"https://github.com/o/r", "", "", false}, // bare repo (no subresource) → fail closed
		{"https://github.com/justowner", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		o, r, ok := repoFromIssueOrPullRef(c.in)
		if ok != c.ok || o != c.owner || r != c.repo {
			t.Errorf("repoFromIssueOrPullRef(%q)=(%q,%q,%v) want (%q,%q,%v)", c.in, o, r, ok, c.owner, c.repo, c.ok)
		}
	}
}
