package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"better-gh/internal/audit"
	"better-gh/internal/gqlfilter"
	"better-gh/internal/policy"
)

// Regression for FINDING N (HIGH): a GraphQL request the filter cannot type (schema drift —
// a field newer than the embedded schema) was forwarded UNFILTERED if the classifier's
// (incomplete) cross-repo-nav denylist did not flag it. A scoped read navigating cross-repo
// via a non-denylisted field (associatedPullRequests) under drift leaked other-repo data.
// The proxy now denies any GraphQL request it cannot type+filter (filter enabled).
func TestSec_E2E_UntypeableGraphQLDenied(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	var hits int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"repository":{"object":{"associatedPullRequests":{"nodes":[{"title":"OTHER_REPO_PR_TITLE"}]}}}}}`)
	}))
	t.Cleanup(upstream.Close)

	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo:     []policy.RepoRule{{Name: "allowed-org/rw-repo", Access: policy.AccessRead}},
	}
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol,
		UpstreamURL: upstream.URL, GQLFilter: sch,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	// driftField2099 is absent from the embedded schema → augmentation fails → no filter.
	drift := `{"query":"query { repository(owner:\"allowed-org\",name:\"rw-repo\"){ object(expression:\"HEAD\"){ ... on Commit { associatedPullRequests(first:5){ nodes { title driftField2099 } } } } } }"}`
	resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(drift))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("untypeable scoped read must be denied, got %d: %s", resp.StatusCode, out)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("denied untypeable read must not reach upstream, got %d hits", n)
	}

	// Control: the same read WITHOUT the drift field types fine → augmented, filtered, allowed.
	ok := `{"query":"query { repository(owner:\"allowed-org\",name:\"rw-repo\"){ object(expression:\"HEAD\"){ ... on Commit { associatedPullRequests(first:5){ nodes { title } } } } } }"}`
	resp2, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(ok))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusForbidden {
		t.Fatalf("a typeable scoped read should be allowed (and filtered), got 403")
	}
}
