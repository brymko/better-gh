package restfilter

import (
	"strings"
	"testing"
)

func allowOnly(allowed ...string) func(string) bool {
	set := map[string]bool{}
	for _, a := range allowed {
		set[a] = true
	}
	return func(repo string) bool { return set[repo] }
}

func TestIsRepoEnumPath(t *testing.T) {
	yes := []string{"/user/repos", "/user/starred", "/user/issues", "/orgs/o/repos", "/orgs/o/issues",
		"/users/u/repos", "/repositories", "/issues", "/search/repositories", "/search/code",
		"/search/issues", "/search/commits"}
	no := []string{"/repos/o/r/pulls", "/repos/o/r", "/user", "/search/users", "/search/topics",
		"/orgs/o", "/orgs/o/members", "/graphql", "/notifications"}
	for _, p := range yes {
		if !IsRepoEnumPath(p) {
			t.Errorf("%s should be a repo-enum path", p)
		}
	}
	for _, p := range no {
		if IsRepoEnumPath(p) {
			t.Errorf("%s should NOT be a repo-enum path", p)
		}
	}
}

func TestFilterRepoArray(t *testing.T) {
	body := []byte(`[{"full_name":"a/keep"},{"full_name":"b/drop","description":"SECRET"},{"owner":{"login":"c"},"name":"keep2"}]`)
	out := Filter("/user/repos", body, allowOnly("a/keep", "c/keep2"))
	s := string(out)
	if strings.Contains(s, "SECRET") || strings.Contains(s, "b/drop") {
		t.Fatalf("denied repo not dropped: %s", s)
	}
	if !strings.Contains(s, "a/keep") || !strings.Contains(s, "keep2") {
		t.Fatalf("allowed repos lost: %s", s)
	}
}

func TestFilterIssueArray(t *testing.T) {
	// /issues and /user/issues return issue objects carrying their repository.
	body := []byte(`[{"title":"ok","repository":{"full_name":"a/keep"}},{"title":"LEAK","repository_url":"https://api.github.com/repos/b/drop"}]`)
	out := Filter("/user/issues", body, allowOnly("a/keep"))
	if strings.Contains(string(out), "LEAK") || strings.Contains(string(out), "b/drop") {
		t.Fatalf("denied-repo issue not dropped: %s", out)
	}
	if !strings.Contains(string(out), "ok") {
		t.Fatalf("allowed issue lost: %s", out)
	}
}

func TestFilterSearchItems(t *testing.T) {
	body := []byte(`{"total_count":2,"incomplete_results":false,"items":[` +
		`{"name":"f","repository":{"full_name":"a/keep"}},` +
		`{"name":"g","repository":{"full_name":"b/drop"},"text_matches":"CODE_LEAK"}]}`)
	out := Filter("/search/code", body, allowOnly("a/keep"))
	s := string(out)
	if strings.Contains(s, "CODE_LEAK") || strings.Contains(s, "b/drop") {
		t.Fatalf("denied repo code not dropped: %s", s)
	}
	if !strings.Contains(s, "a/keep") {
		t.Fatalf("allowed item lost: %s", s)
	}
}

// An undeterminable-repo entry is dropped (fail closed).
func TestFilterDropsUndeterminable(t *testing.T) {
	body := []byte(`[{"unrelated":"x"},{"full_name":"a/keep"}]`)
	out := Filter("/user/repos", body, allowOnly("a/keep"))
	if strings.Contains(string(out), "unrelated") {
		t.Fatalf("entry with no determinable repo must be dropped: %s", out)
	}
	if !strings.Contains(string(out), "a/keep") {
		t.Fatalf("allowed entry lost: %s", out)
	}
}

// An off-shape body (error object on a list path, or no items on a search path) is passed
// through unchanged (defense-in-depth, must not break availability).
func TestFilterPassesThroughOffShape(t *testing.T) {
	errObj := []byte(`{"message":"Not Found","status":"404"}`)
	if string(Filter("/user/repos", errObj, allowOnly())) != string(errObj) {
		t.Fatalf("error object on a list path should pass through unchanged")
	}
	if string(Filter("/search/code", errObj, allowOnly())) != string(errObj) {
		t.Fatalf("object without items on a search path should pass through unchanged")
	}
}
