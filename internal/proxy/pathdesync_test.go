package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"better-gh/internal/audit"
	"better-gh/internal/policy"
)

// Regression: an encoded '?' (or '#') in a path segment must not desync the classifier
// (which sees the decoded path) from the URL the proxy forwards upstream. Policy allows
// org "o" (read) but DENIES repo "o/r" — the documented "read the org, block one repo"
// pattern. A request to /repos/o/r%3Fx/pulls classifies as repo "o/r?x" (org-allowed); if
// the proxy reassembled the DECODED path into a URL string, url.Parse would re-split it at
// the literal '?' and GitHub would serve the DENIED repo "o/r". Forwarding the escaped
// path keeps GitHub routing the exact repo segment ("o/r?x") the classifier checked.
func TestSec_EncodedQueryInRepoSegmentNotDesynced(t *testing.T) {
	var mu sync.Mutex
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath = r.URL.Path
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"full_name":"o/r","private":true,"description":"DENIED_REPO_METADATA"}`)
	}))
	t.Cleanup(upstream.Close)

	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org:      []policy.OrgRule{{Name: "o", Access: policy.AccessRead}},
		Repo:     []policy.RepoRule{{Name: "o/r", Access: policy.AccessNone}},
	}
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol, UpstreamURL: upstream.URL,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	// The denied repo must be blocked on the straight path.
	resp, err := http.Get(srv.URL + "/repos/o/r/pulls")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("straight denied repo should be 403, got %d", resp.StatusCode)
	}

	// Encoded '?' in the repo segment must reach GitHub as the same repo segment the
	// classifier saw ("o/r?x"), never the denied "o/r".
	resp, err = http.Get(srv.URL + "/repos/o/r%3Fx/pulls")
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if gotPath == "/repos/o/r" || gotPath == "/repos/o/r/pulls" {
		t.Fatalf("path desync: classifier authorized o/r?x but upstream received %q (denied repo o/r): %s", gotPath, out)
	}
}
