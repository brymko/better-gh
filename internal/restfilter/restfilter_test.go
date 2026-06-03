package restfilter

import (
	"strings"
	"testing"
)

func allowOnly(allowed ...string) func(string, bool) bool {
	set := map[string]bool{}
	for _, a := range allowed {
		set[a] = true
	}
	return func(repo string, _ bool) bool { return set[repo] }
}

func TestIsRepoEnumPath(t *testing.T) {
	yes := []string{"/user/repos", "/user/starred", "/user/issues", "/orgs/o/repos", "/orgs/o/issues",
		"/users/u/repos", "/repositories", "/issues", "/notifications", "/search/repositories",
		"/search/code", "/search/issues", "/search/commits"}
	no := []string{"/repos/o/r/pulls", "/repos/o/r", "/user", "/search/users", "/search/topics",
		"/orgs/o", "/orgs/o/members", "/graphql", "/repos/o/r/notifications"}
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

// Regression for FINDING L: total_count would otherwise be a denied-repo existence oracle
// (items redacted but count reveals a match exists). When items are dropped it is replaced
// with the kept count and the response flagged incomplete.
func TestFilterSearchClosesCountOracle(t *testing.T) {
	body := []byte(`{"total_count":1,"incomplete_results":false,"items":[{"name":"x","repository":{"full_name":"b/drop"}}]}`)
	out := string(Filter("/search/code", body, allowOnly("a/keep")))
	if strings.Contains(out, `"total_count":1`) {
		t.Fatalf("count oracle not closed (total_count still 1): %s", out)
	}
	if !strings.Contains(out, `"total_count":0`) {
		t.Fatalf("total_count should be set to kept count 0: %s", out)
	}
	if !strings.Contains(out, `"incomplete_results":true`) {
		t.Fatalf("incomplete_results should be set: %s", out)
	}
}

// A search whose page had no denied matches keeps its true count untouched.
func TestFilterSearchKeepsCountWhenNothingDropped(t *testing.T) {
	body := []byte(`{"total_count":42,"items":[{"name":"x","repository":{"full_name":"a/keep"}}]}`)
	out := string(Filter("/search/code", body, allowOnly("a/keep")))
	if !strings.Contains(out, `"total_count":42`) {
		t.Fatalf("true count should be preserved when nothing dropped: %s", out)
	}
}

// /notifications returns threads carrying their repository; denied repos' threads (with
// their issue/PR subject titles) must be dropped.
func TestFilterNotifications(t *testing.T) {
	body := []byte(`[{"subject":{"title":"OK"},"repository":{"full_name":"a/keep"}},{"subject":{"title":"LEAK"},"repository":{"full_name":"b/drop"}}]`)
	out := string(Filter("/notifications", body, allowOnly("a/keep")))
	if strings.Contains(out, "LEAK") || strings.Contains(out, "b/drop") {
		t.Fatalf("denied-repo notification not dropped: %s", out)
	}
	if !strings.Contains(out, "OK") {
		t.Fatalf("allowed notification lost: %s", out)
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
