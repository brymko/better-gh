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
		"/users/u/repos", "/repositories", "/issues", "/notifications", "/search/repositories",
		"/search/code", "/search/issues", "/search/commits"}
	// Cross-ref-only and no-repo endpoints are not enum paths. (Single-repo endpoints like
	// /repos/o/r that echo their own already-authorized repo ARE recognized now — filtering them
	// is a safe no-op — so they're not asserted here.)
	no := []string{"/repos/o/r/pulls", "/user", "/search/users", "/search/topics",
		"/orgs/o", "/orgs/o/members", "/graphql"}
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

// The spec-driven Lookup is the basis for fail-closed REST: a repo-bearing GET → NeedsFilter
// (with locations), a known no-repo GET → Pass, an off-spec path → Unknown (the proxy denies it
// unless the classifier already scoped it to one repo).
func TestLookupDecisions(t *testing.T) {
	if d, locs := Lookup("/orgs/o/secret-scanning/alerts"); d != NeedsFilter || len(locs) == 0 {
		t.Errorf("alerts feed should be NeedsFilter with locations, got %v %v", d, locs)
	}
	if d, _ := Lookup("/orgs/o/members"); d != Pass { // known op, returns users not repos
		t.Errorf("/orgs/o/members should be Pass, got %v", d)
	}
	if d, _ := Lookup("/rate_limit"); d != Pass {
		t.Errorf("/rate_limit should be Pass, got %v", d)
	}
	if d, _ := Lookup("/orgs/o/totally-made-up-endpoint"); d != Unknown {
		t.Errorf("off-spec path should be Unknown (→ proxy fails closed), got %v", d)
	}
	// events repo.name shape and migrations nested arrays are spec-derived, not hand-listed.
	if d, locs := Lookup("/orgs/o/events"); d != NeedsFilter || !contains(locs, "$[].repo.name") {
		t.Errorf("events should carry the repo.name location, got %v", locs)
	}
	if d, locs := Lookup("/orgs/o/migrations"); d != NeedsFilter || !contains(locs, "$[].repositories[].full_name") {
		t.Errorf("migrations should carry the nested repositories[] location, got %v", locs)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// Round-12 audit H4/M2: org-wide alert feeds, events, starred/subscriptions, team repos are now
// repo-enum paths, and repoAllowed understands the repo.name / repo.full_name shapes they use.
func TestIsRepoEnumPath_Round12Additions(t *testing.T) {
	for _, p := range []string{
		"/orgs/o/secret-scanning/alerts", "/orgs/o/dependabot/alerts", "/orgs/o/code-scanning/alerts",
		"/orgs/o/events", "/users/u/events", "/users/u/received_events",
		"/users/u/starred", "/users/u/subscriptions", "/orgs/o/teams/t/repos", "/events",
	} {
		if !IsRepoEnumPath(p) {
			t.Errorf("%s should be a repo-enum path", p)
		}
	}
	// Not over-broad: other org alert subpaths / single-repo alerts stay out.
	for _, p := range []string{"/orgs/o/secret-scanning", "/repos/o/r/secret-scanning/alerts", "/orgs/o/teams/t"} {
		if IsRepoEnumPath(p) {
			t.Errorf("%s should NOT be a repo-enum path", p)
		}
	}
}

func TestFilterSecretScanningAlertsDropsDeniedRepo(t *testing.T) {
	// Org secret-scanning feed: each alert carries the cleartext secret + repository.full_name.
	body := []byte(`[{"secret":"AKIA_VISIBLE","repository":{"full_name":"a/keep"}},` +
		`{"secret":"AKIA_TOPSECRET","repository":{"full_name":"a/denied"}}]`)
	out := string(Filter("/orgs/a/secret-scanning/alerts", body, allowOnly("a/keep")))
	if strings.Contains(out, "AKIA_TOPSECRET") || strings.Contains(out, "a/denied") {
		t.Fatalf("denied repo's secret leaked: %s", out)
	}
	if !strings.Contains(out, "AKIA_VISIBLE") {
		t.Fatalf("allowed repo's alert was wrongly dropped: %s", out)
	}
}

func TestFilterEventsRepoNameShape(t *testing.T) {
	// Events: entry repository is under repo.name as the FULL "owner/repo".
	body := []byte(`[{"type":"PushEvent","repo":{"name":"a/keep"}},{"type":"PushEvent","repo":{"name":"a/denied"}}]`)
	out := string(Filter("/orgs/a/events", body, allowOnly("a/keep")))
	if strings.Contains(out, "a/denied") {
		t.Fatalf("denied repo activity leaked: %s", out)
	}
	if !strings.Contains(out, "a/keep") {
		t.Fatalf("allowed repo activity wrongly dropped: %s", out)
	}
}

func TestFilterStarredStarJSONWrapper(t *testing.T) {
	// star+json Accept wraps the repo: {starred_at, repo:{full_name}}.
	body := []byte(`[{"starred_at":"t","repo":{"full_name":"a/keep"}},{"starred_at":"t","repo":{"full_name":"a/denied"}}]`)
	out := string(Filter("/users/u/starred", body, allowOnly("a/keep")))
	if strings.Contains(out, "a/denied") {
		t.Fatalf("denied starred repo leaked: %s", out)
	}
	if !strings.Contains(out, "a/keep") {
		t.Fatalf("allowed starred repo wrongly dropped: %s", out)
	}
}

// Migrations nest a repositories[] of MANY repos per entry; the denied ones are dropped from
// within each entry while the migration metadata is kept (round-12 follow-up).
func TestFilterMigrationsRedactsNestedRepos(t *testing.T) {
	allow := allowOnly("a/keep")
	// List of migrations, each with a mixed repositories[].
	list := []byte(`[{"id":1,"state":"exported","repositories":[{"full_name":"a/keep"},{"full_name":"a/denied"}]}]`)
	out := string(Filter("/orgs/a/migrations", list, allow))
	if strings.Contains(out, "a/denied") {
		t.Fatalf("denied repo leaked from migration list: %s", out)
	}
	if !strings.Contains(out, "a/keep") || !strings.Contains(out, `"state":"exported"`) {
		t.Fatalf("allowed repo / migration metadata wrongly dropped: %s", out)
	}
	// Single migration object.
	one := []byte(`{"id":2,"repositories":[{"full_name":"a/keep"},{"full_name":"a/denied"}]}`)
	out = string(Filter("/orgs/a/migrations/2", one, allow))
	if strings.Contains(out, "a/denied") || !strings.Contains(out, "a/keep") {
		t.Fatalf("single migration object not redacted correctly: %s", out)
	}
	// The .../repositories sub-path is a plain repo array → standard array filtering.
	repos := []byte(`[{"full_name":"a/keep"},{"full_name":"a/denied"}]`)
	out = string(Filter("/orgs/a/migrations/2/repositories", repos, allow))
	if strings.Contains(out, "a/denied") || !strings.Contains(out, "a/keep") {
		t.Fatalf("migration repositories sub-path not filtered: %s", out)
	}
	for _, p := range []string{"/orgs/a/migrations", "/orgs/a/migrations/2", "/user/migrations",
		"/user/migrations/2", "/orgs/a/migrations/2/repositories", "/user/migrations/2/repositories"} {
		if !IsRepoEnumPath(p) {
			t.Errorf("%s should be a repo-enum path", p)
		}
	}
}

func TestFilterRepoArray(t *testing.T) {
	body := []byte(`[{"full_name":"a/keep"},{"full_name":"b/drop","description":"SECRET"},{"full_name":"c/keep2","owner":{"login":"c"},"name":"keep2"}]`)
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

// TestSingletonSubjectFailsClosed is the audit F4 regression: a single-object endpoint whose whole
// body belongs to one repo (notifications thread, codespace) must FAIL CLOSED when that repo is
// denied — nulling only the $.repository sub-object would leak same-repo siblings (issue/PR titles,
// branch names). An allowed subject passes through; an absent repo identity does not fail.
func TestSingletonSubjectFailsClosed(t *testing.T) {
	deny := func(repo string) bool { return repo == "a/keep" }

	// Denied notification thread: repository denied, subject.title is the leak.
	d, locs := Lookup("/notifications/threads/123")
	if d != NeedsFilter {
		t.Fatalf("notifications thread should be NeedsFilter, got %v", d)
	}
	thread := []byte(`{"repository":{"full_name":"a/denied"},"subject":{"title":"SECRET_ISSUE_TITLE","url":"https://api.github.com/repos/a/denied/issues/7"}}`)
	if out, ok := Redact(thread, locs, deny); ok {
		t.Fatalf("denied-repo thread must fail closed, not return a body: %s", out)
	}

	// Allowed thread passes through unchanged.
	ok2 := []byte(`{"repository":{"full_name":"a/keep"},"subject":{"title":"FINE"}}`)
	if out, ok := Redact(ok2, locs, deny); !ok || !contains2(string(out), "FINE") {
		t.Fatalf("allowed thread should pass through, got ok=%v out=%s", ok, out)
	}

	// Codespace singleton: denied repo must fail closed (git_status.ref / recent_folders leak).
	_, clocs := Lookup("/user/codespaces/my-space")
	cs := []byte(`{"name":"my-space","repository":{"full_name":"a/denied"},"git_status":{"ref":"secret-branch"}}`)
	if _, ok := Redact(cs, clocs, deny); ok {
		t.Fatal("denied-repo codespace must fail closed")
	}
}

func contains2(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}
