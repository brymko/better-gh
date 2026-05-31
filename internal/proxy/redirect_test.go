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

// Regression for FINDING J (HIGH): the proxy auto-followed upstream redirects without
// re-checking the target, so a request to an allowed path could be followed (e.g. via a
// renamed repo's 301) into a denied repo and serve its content. EnforceRedirectPolicy now
// re-classifies same-host redirect targets, while still allowing cross-host CDN downloads.
func TestSec_E2E_RedirectReclassified(t *testing.T) {
	var secretHits int32
	var cdn *httptest.Server
	cdn = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `DOWNLOAD_OK`) // simulates codeload/objects CDN (different host)
	}))
	t.Cleanup(cdn.Close)

	var upstreamURL string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/allowed-org/rw-repo/contents/denied":
			http.Redirect(w, r, upstreamURL+"/repos/blocked-org/secret/contents/x", http.StatusMovedPermanently)
		case "/repos/allowed-org/rw-repo/contents/renamed":
			// same-host redirect to ANOTHER allowed path (repo rename within scope)
			http.Redirect(w, r, upstreamURL+"/repos/allowed-org/rw-repo/contents/final", http.StatusMovedPermanently)
		case "/repos/allowed-org/rw-repo/contents/final":
			io.WriteString(w, `ALLOWED_OK`)
		case "/repos/allowed-org/rw-repo/tarball/main":
			http.Redirect(w, r, cdn.URL+"/legacy.tar.gz", http.StatusFound) // cross-host download
		case "/repos/blocked-org/secret/contents/x":
			atomic.AddInt32(&secretHits, 1)
			io.WriteString(w, `TOPSECRET_REDIRECT`)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(upstream.Close)
	upstreamURL = upstream.URL

	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{
			{Name: "allowed-org/rw-repo", Access: policy.AccessRead},
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

	get := func(path string) (int, string) {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}

	// 1) same-host redirect into a DENIED repo must be blocked (not served).
	if _, body := get("/repos/allowed-org/rw-repo/contents/denied"); strings.Contains(body, "TOPSECRET_REDIRECT") {
		t.Errorf("redirect into denied repo was followed and served: %q", body)
	}
	if n := atomic.LoadInt32(&secretHits); n != 0 {
		t.Errorf("denied repo endpoint must not be fetched on redirect, got %d hits", n)
	}

	// 2) same-host redirect to another ALLOWED path must still be followed.
	if st, body := get("/repos/allowed-org/rw-repo/contents/renamed"); body != "ALLOWED_OK" {
		t.Errorf("allowed same-host redirect should be followed, got status=%d body=%q", st, body)
	}

	// 3) cross-host CDN download redirect must still be followed.
	if st, body := get("/repos/allowed-org/rw-repo/tarball/main"); body != "DOWNLOAD_OK" {
		t.Errorf("cross-host download redirect should be followed, got status=%d body=%q", st, body)
	}
}
