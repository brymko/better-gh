package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"better-gh/internal/audit"
	"better-gh/internal/gqlfilter"
	"better-gh/internal/policy"
)

// Regression for FINDING M (LOW): the upstream X-OAuth-Scopes / X-OAuth-Client-Id /
// X-Accepted-OAuth-Scopes headers reveal the custodian token's reach and must not be
// forwarded to a proxy-token holder.
func TestSec_E2E_UpstreamTokenHeadersStripped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-OAuth-Scopes", "repo, delete_repo, admin:org")
		w.Header().Set("X-Accepted-OAuth-Scopes", "repo")
		w.Header().Set("X-OAuth-Client-Id", "Iv1.deadbeef")
		w.Header().Set("X-RateLimit-Remaining", "4999") // benign header must still pass
		io.WriteString(w, `[]`)
	}))
	t.Cleanup(upstream.Close)
	pol := &policy.Policy{Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{{Name: "o/r", Access: policy.AccessRead}}}
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol, UpstreamURL: upstream.URL,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/repos/o/r/pulls")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, h := range []string{"X-Oauth-Scopes", "X-Accepted-Oauth-Scopes", "X-Oauth-Client-Id"} {
		if v := resp.Header.Get(h); v != "" {
			t.Errorf("%s leaked to client: %q", h, v)
		}
	}
	if resp.Header.Get("X-Ratelimit-Remaining") != "4999" {
		t.Errorf("benign header X-RateLimit-Remaining should still be forwarded")
	}
}

// Regression for FINDING K (extended): /notifications leaks denied-repo issue/PR titles via
// the thread subject; it must be filtered like the other enumeration endpoints.
func TestSec_E2E_NotificationsFiltered(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `[{"subject":{"title":"ALLOWED_TITLE"},"repository":{"full_name":"allowed-org/pub"}},`+
			`{"subject":{"title":"DENIED_PR_TITLE"},"repository":{"full_name":"blocked-org/secret"}}]`)
	}))
	t.Cleanup(upstream.Close)
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny, Unscoped: map[string]policy.Access{"notifications": policy.AccessRead}},
		Repo: []policy.RepoRule{
			{Name: "allowed-org/pub", Access: policy.AccessRead},
			{Name: "blocked-org/secret", Access: policy.AccessNone},
		},
	}
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol, UpstreamURL: upstream.URL, GQLFilter: sch,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/notifications")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(body), "DENIED_PR_TITLE") {
		t.Errorf("/notifications leaked a denied repo's PR title: %s", body)
	}
	if !strings.Contains(string(body), "ALLOWED_TITLE") {
		t.Errorf("/notifications dropped an allowed notification: %s", body)
	}
}
