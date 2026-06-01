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

// Regression: with checks="none" (base=read), commit statuses reached via commit.status
// must be redacted. They are conceptually "checks" but reached under a Commit (resource
// "commits"), so only the type→resource mapping (Status/StatusContext→checks) enforces it.
func TestSec_CommitStatusRedactedUnderChecksNone(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// repository -> object(Commit) -> status(Status) -> contexts(StatusContext)
		io.WriteString(w, `{"data":{"repository":{"bghRepoTagZ9":"o/r","bghRepoTypeZ9":"Repository",`+
			`"object":{"bghRepoTagZ9":{"nameWithOwner":"o/r"},"bghRepoTypeZ9":"Commit",`+
			`"status":{"bghRepoTagZ9":{"nameWithOwner":"o/r"},"bghRepoTypeZ9":"Status",`+
			`"contexts":[{"bghRepoTagZ9":{"nameWithOwner":"o/r"},"bghRepoTypeZ9":"StatusContext","context":"ci","targetUrl":"SECRET_CI_URL"}]}}}}}`)
	}))
	t.Cleanup(upstream.Close)

	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{{
			Name:        "o/r",
			Access:      policy.AccessRead,
			Permissions: map[string]policy.Access{"checks": policy.AccessNone},
		}},
	}
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol,
		UpstreamURL: upstream.URL, GQLFilter: sch,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	q := `query{repository(owner:"o",name:"r"){object(expression:"HEAD"){...on Commit{status{contexts{context targetUrl}}}}}}`
	resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(`{"query":`+jsonStr(q)+`}`))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("status=%d body=%s", resp.StatusCode, out)
	if strings.Contains(string(out), "SECRET_CI_URL") {
		t.Errorf("checks=none NOT enforced on commit Status via GraphQL")
	}
}
