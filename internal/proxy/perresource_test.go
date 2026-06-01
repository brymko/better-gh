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

// Regression for the per-resource GraphQL bypass: a repo readable at base level with
// pulls="none" must not return PR data over GraphQL, even when the query mixes
// pullRequests with a sibling field (which previously downgraded the classified resource
// to "" → base access). The per-resource rule is enforced ONLY by the classifier (the
// response filter is repo-granular), so this query must be denied outright.
func TestSec_PerResourceNotBypassableByMixedSelection(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	var upstreamHit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"repository":{"bghRepoTagZ9":"allowed-org/repo",`+
			`"viewerPermission":"READ","pullRequests":{"nodes":[{"title":"SECRET_PR_TITLE","body":"SECRET_PR_BODY"}]}}}}`)
	}))
	t.Cleanup(upstream.Close)

	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{{
			Name:        "allowed-org/repo",
			Access:      policy.AccessRead,
			Permissions: map[string]policy.Access{"pulls": policy.AccessNone},
		}},
	}
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol,
		UpstreamURL: upstream.URL, GQLFilter: sch,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	// pullRequests mixed with viewerPermission + an unmapped/metadata sibling.
	for _, q := range []string{
		`query{repository(owner:"allowed-org",name:"repo"){pullRequests(first:1){nodes{title body}} viewerPermission}}`,
		`query{repository(owner:"allowed-org",name:"repo"){pullRequests(first:1){nodes{title body}} issues(first:1){nodes{title}}}}`,
		`query{repository(owner:"allowed-org",name:"repo"){...on Repository{pullRequests(first:1){nodes{title body}}}}}`,
	} {
		upstreamHit = false
		body := `{"query":` + jsonStr(q) + `}`
		resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("pulls=none bypass not blocked (status %d) for %q: %s", resp.StatusCode, q, out)
		}
		if upstreamHit {
			t.Fatalf("denied request must not reach upstream for %q", q)
		}
		if strings.Contains(string(out), "SECRET_PR") {
			t.Fatalf("PR data leaked for %q: %s", q, out)
		}
	}
}

func jsonStr(s string) string {
	out := []byte{'"'}
	for _, r := range s {
		switch r {
		case '"':
			out = append(out, '\\', '"')
		case '\\':
			out = append(out, '\\', '\\')
		default:
			out = append(out, string(r)...)
		}
	}
	return string(append(out, '"'))
}
