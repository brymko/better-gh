package restfilter

import (
	"strings"
	"testing"
)

func TestForksPathIsEnum(t *testing.T) {
	if !IsRepoEnumPath("/repos/o/r/forks") {
		t.Fatal("/repos/o/r/forks must be treated as a repo-enumeration path")
	}
	// Not every 4-segment repo path is an enum path.
	if IsRepoEnumPath("/repos/o/r/pulls") {
		t.Fatal("/repos/o/r/pulls must not be a repo-enumeration path")
	}
}

func TestForksDropsDeniedForks(t *testing.T) {
	// /repos/o/r/forks returns repository objects owned by others.
	body := []byte(`[{"full_name":"o/r-fork-allowed"},{"full_name":"blocked/secret-fork"}]`)
	out := Filter("/repos/o/r/forks", body, func(repo string, _ bool) bool { return repo == "o/r-fork-allowed" })
	s := string(out)
	if strings.Contains(s, "secret-fork") {
		t.Fatalf("denied fork not dropped: %s", s)
	}
	if !strings.Contains(s, "r-fork-allowed") {
		t.Fatalf("allowed fork dropped: %s", s)
	}
}
