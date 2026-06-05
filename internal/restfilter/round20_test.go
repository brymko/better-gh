package restfilter

import (
	"strings"
	"testing"
)

func TestR20_EnumContentResource(t *testing.T) {
	cases := map[string]string{
		"/user/issues":      "issues",
		"/issues":           "issues",
		"/search/issues":    "issues",
		"/search/code":      "contents",
		"/search/commits":   "commits",
		"/orgs/acme/issues": "issues",
		"/user/repos":       "", // a repo-enumeration feed (element IS a repo) stays metadata-gated
		"/repos/o/r/pulls":  "", // path-scoped: classifier supplies the resource
	}
	for path, want := range cases {
		if got := EnumContentResource(path); got != want {
			t.Errorf("EnumContentResource(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestR20_HasOpaqueRepoID(t *testing.T) {
	for _, p := range []string{"/agents/tasks", "/agents/tasks/7"} {
		if !HasOpaqueRepoID(p) {
			t.Errorf("HasOpaqueRepoID(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"/agents/repos/o/r/tasks", "/user/repos"} {
		if HasOpaqueRepoID(p) {
			t.Errorf("HasOpaqueRepoID(%q) = true, want false", p)
		}
	}
}

func TestR20_WriteScrubLocations(t *testing.T) {
	if locs := WriteScrubLocations("/repos/o/r/pulls/42"); len(locs) == 0 {
		t.Errorf("PATCH /repos/o/r/pulls/42 must have write-scrub locations")
	}
	if locs := WriteScrubLocations("/repos/o/r"); len(locs) == 0 {
		t.Errorf("PATCH /repos/o/r must have write-scrub locations (parent/source)")
	}
	if locs := WriteScrubLocations("/repos/o/r/issues"); len(locs) != 0 {
		t.Errorf("/repos/o/r/issues must have no write-scrub locations, got %v", locs)
	}
}

func TestR20_RedactOrgNamedRepos(t *testing.T) {
	allow := func(repo string) bool { return repo != "acme/secret" }
	out, ok := RedactOrgNamedRepos([]byte(`[{"id":1,"name":"public"},{"id":2,"name":"secret"}]`), "acme", allow)
	if !ok {
		t.Fatal("RedactOrgNamedRepos returned not-ok on a valid array")
	}
	s := string(out)
	if strings.Contains(s, "secret") {
		t.Fatalf("denied repo name not dropped: %s", s)
	}
	if !strings.Contains(s, "public") {
		t.Fatalf("allowed repo name wrongly dropped: %s", s)
	}
	// No owner → cannot qualify bare names → fail closed.
	if _, ok := RedactOrgNamedRepos([]byte(`[{"id":1,"name":"x"}]`), "", allow); ok {
		t.Fatal("RedactOrgNamedRepos must fail closed without an owner")
	}
}
