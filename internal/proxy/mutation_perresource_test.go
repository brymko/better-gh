package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"better-gh/internal/audit"
	"better-gh/internal/gqlfilter"
	"better-gh/internal/nodecache"
	"better-gh/internal/policy"
)

// A write grant on one resource (pulls) must not read a DENIED resource (issues=none) of
// the SAME repo through the mutation's response payload. The mutation is authorized (pulls
// write via node resolution), but the resource-aware response filter must redact the issues
// the payload navigates to.
func TestSec_MutationPayloadCannotReadDeniedResource(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(body), "nodes(ids") {
			io.WriteString(w, `{"data":{"nodes":[{"__typename":"PullRequest","repository":{"nameWithOwner":"o/rw"}}]}}`)
			return
		}
		// Augmented mutation payload: pullRequest (pulls, kept) -> repository (metadata, kept)
		// -> issues (issues=none, must be redacted).
		io.WriteString(w, `{"data":{"mergePullRequest":{"pullRequest":{`+
			`"bghRepoTagZ9":{"nameWithOwner":"o/rw"},"bghRepoTypeZ9":"PullRequest",`+
			`"repository":{"bghRepoTagZ9":"o/rw","bghRepoTypeZ9":"Repository",`+
			`"issues":{"nodes":[{"title":"DENIED_ISSUE_VIA_MUTATION","bghRepoTagZ9":{"nameWithOwner":"o/rw"},"bghRepoTypeZ9":"Issue"}]}`+
			`}}}}}`)
	}))
	t.Cleanup(upstream.Close)

	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{{
			Name:        "o/rw",
			Access:      policy.AccessRead,
			Permissions: map[string]policy.Access{"pulls": policy.AccessReadWrite, "issues": policy.AccessNone},
		}},
	}
	nc := nodecache.New(time.Minute)
	t.Cleanup(nc.Stop)
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol,
		UpstreamURL: upstream.URL, GQLFilter: sch, NodeCache: nc,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	body := `{"query":"mutation($id:ID!){ mergePullRequest(input:{pullRequestId:$id}){ pullRequest { repository { issues(first:1){ nodes { title } } } } } }","variables":{"id":"PR_node"}}`
	resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(out)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pulls write should be allowed (then payload filtered), got %d: %s", resp.StatusCode, s)
	}
	if strings.Contains(s, "DENIED_ISSUE_VIA_MUTATION") {
		t.Fatalf("issues=none leaked via mutation payload despite pulls write grant: %s", s)
	}
	if strings.Contains(s, "bghRepoTagZ9") || strings.Contains(s, "bghRepoTypeZ9") {
		t.Fatalf("markers leaked: %s", s)
	}
}
