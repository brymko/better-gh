package gqlfilter

import (
	"strings"
	"testing"
)

func TestAugmentInjectsMarkers(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	q := `query { repository(owner:"o", name:"r") { name owner { repositories(first:5) { nodes { name issues(first:1){ nodes { title } } } } } } }`
	out, err := s.Augment(q)
	if err != nil {
		t.Fatalf("augment: %v", err)
	}
	t.Logf("augmented:\n%s", out)
	// the top repository (Repository) gets a nameWithOwner marker; nested repositories
	// (owner.repositories.nodes = Repository) and the nested issues (Issue) get markers too
	if strings.Count(out, markerAlias) < 3 {
		t.Fatalf("expected markers on Repository + nested Repository + Issue, got:\n%s", out)
	}
}

func TestAugmentRejectsInvalid(t *testing.T) {
	s, _ := Load()
	if _, err := s.Augment(`query { repository(owner:"o",name:"r"){ noSuchField } }`); err == nil {
		t.Fatal("expected validation error for unknown field")
	}
}

// A client that pre-declares the reserved marker alias inside a repo-scoped selection
// would suppress our injected repository tag and defeat redaction; Augment must reject it
// (fail closed) so the caller falls back to the cross-repo-nav denial.
func TestAugmentRejectsReservedAlias(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	q := `query { repository(owner:"o", name:"r") { forks(first:5){ nodes { name ` + markerAlias + `: name } } } }`
	if _, err := s.Augment(q); err == nil {
		t.Fatalf("expected Augment to reject a query that uses the reserved marker alias %q", markerAlias)
	}
	// A normal query (no reserved alias) must still augment fine.
	if _, err := s.Augment(`query { repository(owner:"o", name:"r") { name } }`); err != nil {
		t.Fatalf("normal query should augment: %v", err)
	}
}

func TestFilterRedactsDeniedRepos(t *testing.T) {
	// Simulated augmented response: an allowed repo whose owner.repositories includes a
	// denied repo with an issue body.
	resp := map[string]any{
		"data": map[string]any{
			"repository": map[string]any{
				markerAlias: "o/allowed",
				"name":      "allowed",
				"owner": map[string]any{
					"repositories": map[string]any{
						"nodes": []any{
							map[string]any{markerAlias: "o/allowed", "name": "allowed"},
							map[string]any{markerAlias: "o/denied", "name": "denied",
								"issues": map[string]any{"nodes": []any{
									map[string]any{markerAlias: map[string]any{"nameWithOwner": "o/denied"}, "title": "SECRET", "body": "leak-me"},
								}}},
						},
					},
				},
			},
		},
	}
	allowed := func(owner, repo string) bool { return owner == "o" && repo == "allowed" }
	out := Filter(resp, allowed)

	js := mustJSON(out)
	if strings.Contains(js, "leak-me") || strings.Contains(js, "denied") {
		t.Fatalf("denied repo data not redacted: %s", js)
	}
	if !strings.Contains(js, "allowed") {
		t.Fatalf("allowed repo data was lost: %s", js)
	}
	if strings.Contains(js, markerAlias) {
		t.Fatalf("marker not stripped: %s", js)
	}
}

func mustJSON(v any) string {
	var b strings.Builder
	writeJSON(&b, v)
	return b.String()
}

func writeJSON(b *strings.Builder, v any) {
	switch val := v.(type) {
	case map[string]any:
		b.WriteByte('{')
		for k, c := range val {
			b.WriteString(k)
			b.WriteByte(':')
			writeJSON(b, c)
			b.WriteByte(',')
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for _, c := range val {
			writeJSON(b, c)
			b.WriteByte(',')
		}
		b.WriteByte(']')
	case nil:
		b.WriteString("null")
	default:
		b.WriteString(strings.ReplaceAll(strings.TrimSpace(toStr(val)), " ", ""))
	}
}

func toStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	default:
		return ""
	}
}
