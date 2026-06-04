package restfilter

import (
	"strings"
	"testing"
)

// Round-16 LOW: the count-oracle closure must cover enum bodies shaped {total_count, repositories[]}
// (and similar), not only the {total_count, items[]} search shape. Otherwise total_count still
// reveals how many denied repositories were dropped.
func TestCountOracleClosedForRepositoriesArray(t *testing.T) {
	body := []byte(`{"total_count":3,"repositories":[` +
		`{"full_name":"a/keep"},{"full_name":"b/drop"},{"full_name":"c/drop"}]}`)
	out := string(Filter("/installation/repositories", body, allowOnly("a/keep")))
	if strings.Contains(out, "b/drop") || strings.Contains(out, "c/drop") {
		t.Fatalf("denied repositories not dropped: %s", out)
	}
	if strings.Contains(out, `"total_count":3`) {
		t.Fatalf("count oracle not closed (total_count still 3): %s", out)
	}
	if !strings.Contains(out, `"total_count":1`) {
		t.Fatalf("total_count should drop by the 2 removed entries to 1: %s", out)
	}
	if !strings.Contains(out, `"incomplete_results":true`) {
		t.Fatalf("incomplete_results should be set: %s", out)
	}
}

// When nothing is dropped, the true total_count is preserved.
func TestCountOraclePreservedWhenNoRepositoriesDropped(t *testing.T) {
	body := []byte(`{"total_count":7,"repositories":[{"full_name":"a/keep"}]}`)
	out := string(Filter("/installation/repositories", body, allowOnly("a/keep")))
	if !strings.Contains(out, `"total_count":7`) {
		t.Fatalf("true count must be preserved when nothing dropped: %s", out)
	}
}

// Round-16 hardening: ContainsDeniedRepo is the runtime safety net for "Pass" responses the static
// OpenAPI table believed repo-free. It must catch a denied repo surfaced via full_name,
// repository_url, or the minimal {id,name,url} shape — anywhere in the body — without false-positives
// on a branch/file name that merely contains a slash.
func TestContainsDeniedRepo(t *testing.T) {
	auth := allowOnly("ok/keep")
	cases := []struct {
		name      string
		body      string
		wantDeny  bool
		wantParse bool
	}{
		{"denied full_name nested in array", `{"x":[{"full_name":"blocked/secret"}]}`, true, true},
		{"allowed full_name only", `{"x":[{"full_name":"ok/keep"}]}`, false, true},
		{"denied repository_url", `{"items":[{"repository_url":"https://api.github.com/repos/blocked/secret"}]}`, true, true},
		{"allowed repository_url", `{"items":[{"repository_url":"https://api.github.com/repos/ok/keep/issues/1"}]}`, false, true},
		{"denied minimal repo shape", `[{"repo":{"id":5,"name":"blocked/secret","url":"u"}}]`, true, true},
		{"branch name with slash is NOT a repo (no id/url)", `{"ref":{"name":"release/v1"}}`, false, true},
		{"empty body", ``, false, true},
		{"non-JSON body", "not json at all", false, false},
		{"no repo anywhere", `{"login":"someone","plan":{"name":"pro"}}`, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			denied, ok := ContainsDeniedRepo([]byte(c.body), auth)
			if denied != c.wantDeny || ok != c.wantParse {
				t.Fatalf("got (denied=%v, parsedOK=%v), want (%v, %v)", denied, ok, c.wantDeny, c.wantParse)
			}
		})
	}
}
