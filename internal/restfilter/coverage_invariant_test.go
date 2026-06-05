package restfilter

import (
	"strings"
	"testing"
)

// nestsRepoInElement reports whether any of an enum op's repo locations nests the repository INSIDE the
// array element (the repo is reached via an intermediate field — `$[].repository.full_name`,
// `$[].payload.issue.repository.full_name`, `$.items[].repository.full_name`) rather than the element
// being the repository itself (`$[].full_name`). A nesting element exposes per-repo CONTENT (or the repo
// a codespace/package/alert belongs to), so its per-resource gate matters; an element that IS a repo is
// metadata by construction and gated correctly at base.
func nestsRepoInElement(locs []string) bool {
	for _, loc := range locs {
		i := strings.LastIndex(loc, "[]")
		if i < 0 {
			continue // singleton location (path-scoped subject repo) — handled by the classifier/Redact
		}
		suffix := loc[i+2:]
		segs := 0
		for _, s := range strings.Split(suffix, ".") {
			if s != "" {
				segs++
			}
		}
		if segs >= 2 {
			return true
		}
	}
	return false
}

// TestCoverage_NestedRepoEnumOps is the PERMANENT, spec-coupled guard against the round-18-D / round-20 /
// round-21 content-feed leak class: a NeedsFilter enum op whose element NESTS a repository must be
// explicitly classified as either a CONTENT feed (contentEnumResourceOps — gets a content per-resource
// key) or a reviewed METADATA feed (metadataNestedRepoEnumOps). It re-derives the nests-a-repo set from
// the GENERATED repoEnumOps, so a spec refresh that adds a new content feed (e.g. the round-21 events
// family) FAILS THE BUILD until it is classified — instead of silently defaulting to a metadata-only
// keep-gate and leaking issue/PR content under a per-resource carve-out. This replaces per-round hand-
// chasing of content-feed siblings with a build-time invariant on the restfilter side (the GraphQL side
// already has its coverage invariants).
func TestCoverage_NestedRepoEnumOps(t *testing.T) {
	var unclassified, doubleClassified []string
	for key, locs := range repoEnumOps {
		path := strings.TrimPrefix(key, "GET ")
		if !nestsRepoInElement(locs) {
			continue
		}
		_, isContent := contentEnumResourceOps[path]
		_, isMeta := metadataNestedRepoEnumOps[path]
		if !isContent && !isMeta {
			unclassified = append(unclassified, path)
		}
		if isContent && isMeta {
			doubleClassified = append(doubleClassified, path)
		}
	}
	if len(unclassified) > 0 {
		t.Fatalf("nests-a-repo enum op(s) classified as NEITHER content nor reviewed-metadata — they would "+
			"default to a metadata-only keep-gate and leak per-repo content under a carve-out (round-21). "+
			"Add each to contentEnumResourceOps (with its content key) or metadataNestedRepoEnumOps (with a "+
			"review reason):\n  %s", strings.Join(unclassified, "\n  "))
	}
	if len(doubleClassified) > 0 {
		t.Fatalf("enum op(s) in BOTH content and metadata tables (ambiguous):\n  %s", strings.Join(doubleClassified, "\n  "))
	}
}

// TestCoverage_ContentEnumOpsAreReal asserts every contentEnumResourceOps / metadataNestedRepoEnumOps key
// is a real NeedsFilter (repoEnumOps) op, so a content/metadata tag cannot be a DEAD entry (a typo'd path
// that never matches a request and silently provides no gate).
func TestCoverage_ContentEnumOpsAreReal(t *testing.T) {
	live := map[string]bool{}
	for key := range repoEnumOps {
		live[strings.TrimPrefix(key, "GET ")] = true
	}
	for path := range contentEnumResourceOps {
		if !live[path] {
			t.Errorf("contentEnumResourceOps[%q] is not a NeedsFilter (repoEnumOps) op — dead/typo'd entry", path)
		}
	}
	for path := range metadataNestedRepoEnumOps {
		if !live[path] {
			t.Errorf("metadataNestedRepoEnumOps[%q] is not a NeedsFilter (repoEnumOps) op — dead/typo'd entry", path)
		}
	}
}

// TestCoverage_HandTablePathsValid asserts every hand-maintained restfilter table path parses to a
// non-empty segment template, catching a typo'd template that silently never matches.
func TestCoverage_HandTablePathsValid(t *testing.T) {
	check := func(name, path string) {
		if len(segments(path)) == 0 {
			t.Errorf("%s path %q parses to an empty template (typo?)", name, path)
		}
	}
	for k := range writeScrubOps {
		check("writeScrubOps", k)
	}
	for k := range repoScrubOps {
		check("repoScrubOps", strings.TrimPrefix(k, "GET "))
	}
	for _, p := range opaqueRepoIDOps {
		check("opaqueRepoIDOps", p)
	}
	for _, p := range orgNamedRepoArrayOps {
		check("orgNamedRepoArrayOps", p)
	}
	for k := range repoStringArrayOps {
		check("repoStringArrayOps", strings.TrimPrefix(k, "GET "))
	}
}
