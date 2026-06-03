package gqlfilter

import (
	"strings"
	"testing"
)

// Documents FINDING P (information disclosure, NON-boundary): the filter redacts denied-repo
// CONTENT but deliberately does not touch connection/search COUNT scalars (totalCount,
// issueCount, …). Those are computed by GitHub over the full pre-redaction set, so they
// reveal the count/existence of denied items; this is not soundly closable in the response
// filter (count fields can be aliased, totalCount is a cross-page total). The fine-grained
// upstream PAT is the bound. This test pins the behavior so the docs stay truthful — if a
// future change starts adjusting counts, update the security model accordingly.
func TestFilter_RedactsContentNotCounts(t *testing.T) {
	resp := map[string]any{"data": map[string]any{"search": map[string]any{
		"issueCount": float64(2),
		"nodes": []any{
			map[string]any{markerAlias: map[string]any{"nameWithOwner": "o/allowed"}, "title": "ok"},
			map[string]any{markerAlias: map[string]any{"nameWithOwner": "o/denied"}, "title": "DENIED_BODY"},
		},
	}}}
	out := Filter(resp, func(owner, repo, _ string, _ bool) bool { return repo == "allowed" })
	js := mustJSON(out)

	// CONTENT of the denied repo is redacted (the guarantee that holds).
	if strings.Contains(js, "DENIED_BODY") {
		t.Fatalf("denied content must be redacted: %s", js)
	}
	// COUNT is intentionally NOT adjusted (documented non-boundary). If this ever changes,
	// the README/SPEC "counts and aggregates leak" note must be revised.
	if !strings.Contains(js, `issueCount`) {
		t.Fatalf("count field unexpectedly removed — security model docs are now stale: %s", js)
	}
}
