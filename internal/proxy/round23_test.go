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

// TestSec_R23_RepoOwnerMemberBypass: members="none" must hold on the repository().owner navigation path,
// not just the organization(login:) root — the round-23 H-1 sibling. The query must be denied outright
// (the member roster is not repo-scoped, so the response filter cannot redact it; the classifier is the
// only defense).
func TestSec_R23_RepoOwnerMemberBypass(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	var upstreamHit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"repository":{"bghRepoTagZ9":"acme/repo","owner":{"membersWithRole":{"nodes":[{"login":"SECRET_ADMIN"}]}}}}}`)
	}))
	t.Cleanup(upstream.Close)
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org:      []policy.OrgRule{{Name: "acme", Access: policy.AccessRead, Permissions: map[string]policy.Access{"members": policy.AccessNone}}},
	}
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol, UpstreamURL: upstream.URL, GQLFilter: sch,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	q := `query{repository(owner:"acme",name:"repo"){owner{...on Organization{membersWithRole(first:10){nodes{login}}}}}}`
	resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(`{"query":`+jsonStr(q)+`}`))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("repository().owner members=none bypass not blocked (status %d): %s", resp.StatusCode, out)
	}
	if upstreamHit || strings.Contains(string(out), "SECRET_ADMIN") {
		t.Fatalf("member roster leaked via repository().owner: hit=%v body=%s", upstreamHit, out)
	}
}

// TestSec_R23_MigrationDeniedRepoBody: POST /orgs/{org}/migrations naming a DENIED repo in its body must be
// rejected (round-23 H-2) — otherwise the custodian archives the denied repo for the client to download.
func TestSec_R23_MigrationDeniedRepoBody(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org:      []policy.OrgRule{{Name: "acme", Access: policy.AccessRead, Permissions: map[string]policy.Access{"migrations": policy.AccessReadWrite}}},
		Repo:     []policy.RepoRule{{Name: "acme/secret", Access: policy.AccessNone}},
	}
	var upstreamHit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		io.WriteString(w, `{"id":1,"repositories":[{"full_name":"acme/secret"}]}`)
	}))
	t.Cleanup(upstream.Close)
	srv := httptest.NewServer(r15Handler(t, pol, upstream.URL))
	t.Cleanup(srv.Close)
	resp, err := http.Post(srv.URL+"/orgs/acme/migrations", "application/json", strings.NewReader(`{"repositories":["acme/secret"],"lock_repositories":false}`))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("migration of a denied repo not blocked (status %d): %s", resp.StatusCode, out)
	}
	if upstreamHit {
		t.Fatal("denied migration must not reach upstream (custodian must not archive the denied repo)")
	}
}

// TestSec_R23_VariantAnalysisContentScrub: a variant-analysis whose body uses repository_lists (which the
// classifier cannot resolve offline) must still not echo a denied repo's identity — the response
// scanned_repositories/skipped_repositories are content-scrubbed (round-23 M-1).
func TestSec_R23_VariantAnalysisContentScrub(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo:     []policy.RepoRule{{Name: "o/r", Access: policy.AccessReadWrite}},
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":7,"controller_repo":{"full_name":"o/r"},"scanned_repositories":[{"repository":{"full_name":"acme/secret","private":true}}]}`)
	}))
	t.Cleanup(upstream.Close)
	srv := httptest.NewServer(r15Handler(t, pol, upstream.URL))
	t.Cleanup(srv.Close)
	resp, err := http.Post(srv.URL+"/repos/o/r/code-scanning/codeql/variant-analyses", "application/json",
		strings.NewReader(`{"language":"go","query_pack":"x","repository_lists":["mylist"]}`))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(out), "acme/secret") {
		t.Fatalf("variant-analysis echoed a denied repo's identity: %s", out)
	}
}
