package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"better-gh/internal/audit"
	"better-gh/internal/policy"
)

// TestR19_RedirectToEnumerationRefused is the regression for round-19 F1: respFilter/passScan are
// fixed once for the REQUESTED endpoint, so a no-filter path-scoped read (contents) that upstream
// redirects SAME-HOST to a cross-repo ENUMERATION endpoint (/user/repos) would stream that body
// unredacted even though the original path produced no filter. EnforceRedirectPolicy must refuse a
// same-host redirect whose origin/target are not both single-repo, so the enumeration body is never
// fetched.
func TestR19_RedirectToEnumerationRefused(t *testing.T) {
	var userReposHits int32
	var upstreamURL string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/allowed-org/pub/contents/x":
			// adversarial upstream redirects a path-scoped read to a cross-repo enumeration endpoint
			http.Redirect(w, r, upstreamURL+"/user/repos", http.StatusMovedPermanently)
		case "/user/repos":
			atomic.AddInt32(&userReposHits, 1)
			io.WriteString(w, `[{"full_name":"blocked-org/secret","private":true}]`)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(upstream.Close)
	upstreamURL = upstream.URL

	pol := &policy.Policy{
		// /user/repos would be ALLOWED by policy if the redirect were followed (unscoped user=read),
		// so only the filter-shape guard stops the leak — not the authorization re-check.
		Defaults: policy.Defaults{Mode: policy.ModeDeny, Unscoped: map[string]policy.Access{"user": policy.AccessRead}},
		Repo: []policy.RepoRule{
			{Name: "allowed-org/pub", Access: policy.AccessRead},
			{Name: "blocked-org/secret", Access: policy.AccessNone},
		},
	}
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{CheckRedirect: EnforceRedirectPolicy},
		Mode:   SocketMode, SocketPolicy: pol, UpstreamURL: upstream.URL,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/repos/allowed-org/pub/contents/x")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if strings.Contains(string(body), "blocked-org/secret") {
		t.Errorf("enumeration redirect leaked a denied repo: %q", string(body))
	}
	if n := atomic.LoadInt32(&userReposHits); n != 0 {
		t.Errorf("the cross-repo enumeration endpoint must not be fetched on a same-host redirect, got %d hits", n)
	}
}
