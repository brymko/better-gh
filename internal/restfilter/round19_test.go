package restfilter

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestR19_VariantAnalysisNotFoundReposScrubbed pins round-19 F4: the CodeQL variant analysis names
// some repos as bare strings in not_found_repos.repository_full_names, which the generator can't
// locate. DropRepoStrings must drop denied "owner/repo" strings and decrement the sibling count,
// while keeping allowed ones.
func TestR19_VariantAnalysisNotFoundReposScrubbed(t *testing.T) {
	path := "/repos/ctrl/repo/code-scanning/codeql/variant-analyses/123"
	locs := StringArrayLocations(path)
	if len(locs) == 0 {
		t.Fatalf("no string-array locations for %q; the variant-analyses op must be covered", path)
	}
	body := []byte(`{
		"skipped_repositories": {
			"not_found_repos": {
				"repository_count": 3,
				"repository_full_names": ["allowed/ok", "secret/denied1", "secret/denied2"]
			}
		}
	}`)
	authorized := func(ownerRepo string) bool { return !strings.HasPrefix(ownerRepo, "secret/") }
	out, ok := DropRepoStrings(body, locs, authorized)
	if !ok {
		t.Fatal("DropRepoStrings failed to parse a well-formed body")
	}
	s := string(out)
	for _, denied := range []string{"secret/denied1", "secret/denied2"} {
		if strings.Contains(s, denied) {
			t.Errorf("denied repo name %q leaked in not_found_repos: %s", denied, s)
		}
	}
	if !strings.Contains(s, "allowed/ok") {
		t.Errorf("allowed repo name was wrongly dropped: %s", s)
	}
	// count must be reduced from 3 to 1 (two denied dropped).
	var parsed struct {
		Skipped struct {
			NotFound struct {
				Count json.Number `json:"repository_count"`
			} `json:"not_found_repos"`
		} `json:"skipped_repositories"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Skipped.NotFound.Count.String() != "1" {
		t.Errorf("repository_count = %s, want 1 (oracle: count must drop with the names)", parsed.Skipped.NotFound.Count)
	}
}

// fail closed on an unparseable body (matching Redact/Scrub).
func TestR19_DropRepoStringsFailsClosed(t *testing.T) {
	locs := StringArrayLocations("/repos/ctrl/repo/code-scanning/codeql/variant-analyses/123")
	if _, ok := DropRepoStrings([]byte("}{ not json"), locs, func(string) bool { return true }); ok {
		t.Error("DropRepoStrings must fail closed (ok=false) on an unparseable body")
	}
}
