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

// End-to-end: with defaults.public=read and NO explicit rules, a GraphQL read of a PUBLIC repo
// is allowed and returned, while a PRIVATE repo named in the same query is redacted — proving
// the baseline forwards reads and the gqlfilter gates per object using GitHub's real isPrivate.
func TestSec_E2E_PublicBaseline_GraphQL(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{`+
			`"pub":{"bghRepoTagZ9":"o/pubrepo","bghRepoTypeZ9":"Repository","bghRepoVisZ9":false,"name":"PUBLIC_REPO_DATA"},`+
			`"priv":{"bghRepoTagZ9":"o/privrepo","bghRepoTypeZ9":"Repository","bghRepoVisZ9":true,"name":"PRIVATE_REPO_DATA"}`+
			`}}`)
	}))
	t.Cleanup(upstream.Close)

	pol := &policy.Policy{Defaults: policy.Defaults{Mode: policy.ModeDeny, Public: policy.AccessRead}}
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol,
		UpstreamURL: upstream.URL, GQLFilter: sch,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	q := `query{pub:repository(owner:"o",name:"pubrepo"){name} priv:repository(owner:"o",name:"privrepo"){name}}`
	resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(`{"query":`+jsonStr(q)+`}`))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(out)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("public-baseline read should be 200, got %d: %s", resp.StatusCode, s)
	}
	if !strings.Contains(s, "PUBLIC_REPO_DATA") {
		t.Fatalf("public repo was not readable under defaults.public=read: %s", s)
	}
	if strings.Contains(s, "PRIVATE_REPO_DATA") {
		t.Fatalf("LEAK: private repo readable under the public baseline: %s", s)
	}
	if strings.Contains(s, "bghRepoVisZ9") {
		t.Fatalf("visibility marker leaked to client: %s", s)
	}
}

// End-to-end: a REST repo-scoped read (GET /repos/o/r) under defaults.public=read is allowed
// for a PUBLIC repo (visibility looked up authoritatively) and DENIED for a private one — the
// private repo's contents are never fetched for the client (only the visibility GET is made).
func TestSec_E2E_PublicBaseline_RESTRepoScoped(t *testing.T) {
	var privContentFetched bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/o/pubrepo":
			io.WriteString(w, `{"full_name":"o/pubrepo","private":false,"visibility":"public","name":"pubrepo","description":"PUBLIC_OK"}`)
		case "/repos/o/privrepo":
			// Hit by the visibility lookup; the response's private=true must lead to a deny
			// BEFORE any content is returned to the client.
			io.WriteString(w, `{"full_name":"o/privrepo","private":true,"visibility":"private","name":"privrepo","description":"PRIVATE_SECRET"}`)
		default:
			io.WriteString(w, `{}`)
		}
	}))
	t.Cleanup(upstream.Close)

	pol := &policy.Policy{Defaults: policy.Defaults{Mode: policy.ModeDeny, Public: policy.AccessRead}}
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol, UpstreamURL: upstream.URL,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	// Public repo → allowed, content returned.
	resp, err := http.Get(srv.URL + "/repos/o/pubrepo")
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("public repo GET should be 200, got %d: %s", resp.StatusCode, out)
	}
	if !strings.Contains(string(out), "PUBLIC_OK") {
		t.Fatalf("public repo content not returned: %s", out)
	}

	// Private repo → denied (403), content never streamed.
	resp2, err := http.Get(srv.URL + "/repos/o/privrepo")
	if err != nil {
		t.Fatal(err)
	}
	out2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("private repo GET under public=read should be 403, got %d: %s", resp2.StatusCode, out2)
	}
	if strings.Contains(string(out2), "PRIVATE_SECRET") {
		t.Fatalf("LEAK: private repo content returned to client: %s", out2)
	}
	_ = privContentFetched
}

// A WRITE to a public repo is NOT granted by the baseline (it is read-only); an explicit
// [[repo]] rule is required. The request must be denied before any upstream write.
func TestSec_E2E_PublicBaseline_WriteDenied(t *testing.T) {
	var upstreamHit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		io.WriteString(w, `{}`)
	}))
	t.Cleanup(upstream.Close)

	pol := &policy.Policy{Defaults: policy.Defaults{Mode: policy.ModeDeny, Public: policy.AccessRead}}
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol, UpstreamURL: upstream.URL,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp, err := http.Post(srv.URL+"/repos/o/pubrepo/issues", "application/json", strings.NewReader(`{"title":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("write to a public repo under read-only baseline should be 403, got %d", resp.StatusCode)
	}
	if upstreamHit {
		t.Fatal("denied write must not reach the upstream")
	}
}
