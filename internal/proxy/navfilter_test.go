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

// Resource-aware filter: pulls="none" on a readable repo must hold even when the restricted
// resource is reached by NAVIGATING back to the same repo (owner.repository(name:)), which
// the repo-granular filter could not catch. The mock returns what GitHub would for the
// augmented query — repo markers (bghRepoTagZ9) AND type markers (bghRepoTypeZ9). The PR
// node (type PullRequest → resource "pulls") must be redacted; the repo metadata kept.
func TestSec_PerResourceEnforcedThroughNavigation(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"repository":{`+
			`"bghRepoTagZ9":"o/r","bghRepoTypeZ9":"Repository","name":"r",`+
			`"owner":{"repository":{`+
			`"bghRepoTagZ9":"o/r","bghRepoTypeZ9":"Repository",`+
			`"pullRequests":{"nodes":[{"title":"NAV_SECRET_PR","bghRepoTagZ9":{"nameWithOwner":"o/r"},"bghRepoTypeZ9":"PullRequest"}]},`+
			`"issues":{"nodes":[{"title":"ALLOWED_ISSUE","bghRepoTagZ9":{"nameWithOwner":"o/r"},"bghRepoTypeZ9":"Issue"}]}`+
			`}}}}}`)
	}))
	t.Cleanup(upstream.Close)

	// Repo readable; pulls denied, issues allowed (the default base read covers issues).
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{{
			Name:        "o/r",
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

	q := `query{repository(owner:"o",name:"r"){name owner{repository(name:"r"){pullRequests(first:1){nodes{title}} issues(first:1){nodes{title}}}}}}`
	resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(`{"query":`+jsonStr(q)+`}`))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(out)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("query touching a readable repo should be 200 (issues allowed), got %d: %s", resp.StatusCode, s)
	}
	if strings.Contains(s, "NAV_SECRET_PR") {
		t.Fatalf("pulls=none NOT enforced through navigation — PR leaked: %s", s)
	}
	if !strings.Contains(s, "ALLOWED_ISSUE") {
		t.Fatalf("over-redaction: issues (allowed) were dropped: %s", s)
	}
	if strings.Contains(s, "bghRepoTagZ9") || strings.Contains(s, "bghRepoTypeZ9") {
		t.Fatalf("injected markers leaked to client: %s", s)
	}
}

// No over-redaction for the base="none" + per-resource "read" pattern ("read only this
// repo's issues"): the repository container must survive (else the granted issues are lost
// with it), the issues kept, and the un-granted pulls redacted.
func TestSec_BaseNonePerResourceReadKeepsContainer(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Under base=none the classifier only lets the granted resource (issues) be queried,
		// so the response is the repository container + its issues. The container must NOT be
		// redacted (its resource is "metadata" but the repo is readable via issues=read), or
		// the granted issues vanish with it.
		io.WriteString(w, `{"data":{"repository":{`+
			`"bghRepoTagZ9":"o/r","bghRepoTypeZ9":"Repository",`+
			`"issues":{"nodes":[{"title":"GRANTED_ISSUE","bghRepoTagZ9":{"nameWithOwner":"o/r"},"bghRepoTypeZ9":"Issue"}]}`+
			`}}}`)
	}))
	t.Cleanup(upstream.Close)

	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{{
			Name:        "o/r",
			Access:      policy.AccessNone, // base none: only the granted resource is readable
			Permissions: map[string]policy.Access{"issues": policy.AccessRead},
		}},
	}
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol,
		UpstreamURL: upstream.URL, GQLFilter: sch,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	q := `query{repository(owner:"o",name:"r"){issues(first:1){nodes{title}}}}`
	resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(`{"query":`+jsonStr(q)+`}`))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(out)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("issues-only query under issues=read should be 200, got %d: %s", resp.StatusCode, s)
	}
	if !strings.Contains(s, "GRANTED_ISSUE") {
		t.Fatalf("over-redaction: granted issues lost (container wrongly redacted): %s", s)
	}
}
