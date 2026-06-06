package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"better-gh/internal/policy"
)

// TestSec_R30_UserPrivateCollectionsDenied: the loginflow "user" floor must NOT grant the custodian's
// private /user/* account collections — a mode=deny token reading /user/emails|orgs|keys must be denied,
// while /user/repos (a repo-filtered feed the floor exists for) is allowed (round-30 HIGH-1).
func TestSec_R30_UserPrivateCollectionsDenied(t *testing.T) {
	pol := &policy.Policy{Defaults: policy.Defaults{Mode: policy.ModeDeny,
		Unscoped: map[string]policy.Access{"user": policy.AccessRead, "meta": policy.AccessRead}}}
	var hit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		io.WriteString(w, `[{"email":"owner-secret@private.example"}]`)
	}))
	t.Cleanup(upstream.Close)
	srv := httptest.NewServer(r15Handler(t, pol, upstream.URL))
	t.Cleanup(srv.Close)
	for _, p := range []string{"/user/emails", "/user/orgs", "/user/keys", "/user/installations"} {
		hit = false
		resp, _ := http.Get(srv.URL + p)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: private account collection not denied (status %d): %s", p, resp.StatusCode, b)
		}
		if hit {
			t.Errorf("%s: denied private collection reached upstream", p)
		}
	}
	// /user/repos (the repo-filtered feed the floor exists for) must NOT be 403.
	resp, _ := http.Get(srv.URL + "/user/repos")
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Errorf("/user/repos wrongly denied (the floor must still enable gh repo list), status %d", resp.StatusCode)
	}
}

// TestSec_R30_RuleSuitesDeniedRepoScrub: an org-scoped Pass feed naming a denied repo by
// {repository_id, repository_name} (bare) or repository_full_name must fail closed (round-30 HIGH-2).
func TestSec_R30_RuleSuitesDeniedRepoScrub(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org:      []policy.OrgRule{{Name: "acme", Access: policy.AccessRead}},
		Repo:     []policy.RepoRule{{Name: "acme/secret-product", Access: policy.AccessNone}},
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `[{"id":1,"repository_id":42,"repository_name":"secret-product","actor_name":"x","before_sha":"DEADBEEF","result":"pass"}]`)
	}))
	t.Cleanup(upstream.Close)
	srv := httptest.NewServer(r15Handler(t, pol, upstream.URL))
	t.Cleanup(srv.Close)
	resp, _ := http.Get(srv.URL + "/orgs/acme/rulesets/rule-suites")
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(b), "secret-product") || strings.Contains(string(b), "DEADBEEF") {
		t.Fatalf("denied repo's rule-suite leaked via bare repository_name: %s", b)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("rule-suite naming a denied repo must fail closed, got status %d: %s", resp.StatusCode, b)
	}
}
