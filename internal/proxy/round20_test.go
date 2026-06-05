package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"better-gh/internal/policy"
)

// Round-20 HIGH #1: the per-resource enum keep-gate must apply to the NON-path-scoped content feeds
// (/user/issues, /search/issues, /issues) too, not only /orgs/{org}/issues. A repo with base=read but
// issues="none" must NOT surface its issue title/body through these feeds, which classify to an
// unscoped category (so classified.Resource was "" → the gate degenerated to metadata → leak).
func TestSec_R20_ContentFeedsPerResourceDeny(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny, Unscoped: map[string]policy.Access{
			"user": policy.AccessRead, "search": policy.AccessRead,
		}},
		Org: []policy.OrgRule{{Name: "acme", Access: policy.AccessRead}},
		Repo: []policy.RepoRule{{
			Name: "acme/crown", Access: policy.AccessRead,
			Permissions: map[string]policy.Access{"issues": policy.AccessNone},
		}},
	}
	arrayFeed := `[{"title":"SECRET_ISSUE","body":"x","repository":{"full_name":"acme/crown"}},` +
		`{"title":"OK_ISSUE","body":"y","repository":{"full_name":"acme/open"}}]`
	searchFeed := `{"total_count":2,"incomplete_results":false,"items":[` +
		`{"title":"SECRET_ISSUE","repository":{"full_name":"acme/crown"}},` +
		`{"title":"OK_ISSUE","repository":{"full_name":"acme/open"}}]}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/search/") {
			io.WriteString(w, searchFeed)
		} else {
			io.WriteString(w, arrayFeed)
		}
	}))
	t.Cleanup(upstream.Close)
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	// /user/issues and /search/issues are reachable under mode=deny via the user/search unscoped grants.
	for _, path := range []string{"/user/issues", "/search/issues?q=org:acme"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		s := string(b)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s expected 200, got %d: %s", path, resp.StatusCode, s)
		}
		if strings.Contains(s, "SECRET_ISSUE") || strings.Contains(s, "acme/crown") {
			t.Fatalf("%s leaked issues=none repo content: %s", path, s)
		}
		if !strings.Contains(s, "OK_ISSUE") {
			t.Fatalf("%s wrongly dropped the allowed repo's issue: %s", path, s)
		}
	}

	// /issues classifies to an EMPTY unscoped category (front-gate denied under mode=deny — so the
	// content-feed fix matters under mode=allow): a base=read + issues=none repo must still be dropped.
	allowPol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeAllow},
		Repo: []policy.RepoRule{{
			Name: "acme/crown", Access: policy.AccessRead,
			Permissions: map[string]policy.Access{"issues": policy.AccessNone},
		}},
	}
	ha := r15Handler(t, allowPol, upstream.URL)
	sa := httptest.NewServer(ha)
	t.Cleanup(sa.Close)
	resp, err := http.Get(sa.URL + "/issues")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if s := string(b); resp.StatusCode != http.StatusOK {
		t.Fatalf("/issues (mode=allow) expected 200, got %d: %s", resp.StatusCode, s)
	} else if strings.Contains(s, "SECRET_ISSUE") || strings.Contains(s, "acme/crown") {
		t.Fatalf("/issues (mode=allow) leaked issues=none repo content: %s", s)
	} else if !strings.Contains(s, "OK_ISSUE") {
		t.Fatalf("/issues (mode=allow) wrongly dropped the allowed repo's issue: %s", s)
	}
}

// Round-20 HIGH #2: the global agent-task lookups /agents/tasks[/{id}] name their repo only by a
// numeric id ContainsDeniedRepo cannot map, so under default=allow they must FAIL CLOSED (the
// path-scoped /agents/repos/{o}/{r}/... form stays scoped by the classifier).
func TestSec_R20_AgentTasksGlobalFailClosed(t *testing.T) {
	pol := &policy.Policy{Defaults: policy.Defaults{Mode: policy.ModeAllow}}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":7,"name":"do thing","repository_id":99,"state":"completed"}`)
	}))
	t.Cleanup(upstream.Close)
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	for _, path := range []string{"/agents/tasks", "/agents/tasks/7"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s must fail closed (403) under default=allow, got %d", path, resp.StatusCode)
		}
	}
}

// Round-20 MEDIUM: a node(id:)/nodes(ids:) read that resolves to an ORG/USER-owned Node type
// (Organization/Team/ProjectV2/…) must fail closed under default=allow, so it cannot bypass an
// [[org]] deny — the owner-level analogue of the round-16 repo-node fail-closed.
func TestSec_R20_OwnerOwnedNodeReadFailsClosed(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeAllow},
		Org:      []policy.OrgRule{{Name: "victim-org", Access: policy.AccessNone}},
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Answer the resolve query: the node is an Organization (no repository).
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"nodes":[{"__typename":"Organization"}]}}`)
	}))
	t.Cleanup(upstream.Close)
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp := postGQL(t, srv.URL, `query { node(id:"O_kgDOABCDEF"){ ... on Organization { login email } } }`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("node(id:Organization) read must fail closed under default=allow, got %d", resp.StatusCode)
	}
}

// Round-20 MEDIUM: GraphQL owner-root reads must enforce org per-resource policy ([org.permissions]
// members="none") like the REST /orgs/{org}/members path, instead of falling through to base org read.
func TestSec_R20_GraphQLOrgPerResourceDeny(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org: []policy.OrgRule{{
			Name: "acme", Access: policy.AccessRead,
			Permissions: map[string]policy.Access{"members": policy.AccessNone},
		}},
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"organization":{"name":"Acme"}}}`)
	}))
	t.Cleanup(upstream.Close)
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	// membersWithRole → gated on "members" = none → 403.
	deny := postGQL(t, srv.URL, `{ organization(login:"acme"){ membersWithRole(first:50){ nodes{ login email } } } }`)
	deny.Body.Close()
	if deny.StatusCode != http.StatusForbidden {
		t.Fatalf("organization{membersWithRole} under members=none must be 403, got %d", deny.StatusCode)
	}
	// Plain org metadata read stays allowed at base org read.
	ok := postGQL(t, srv.URL, `{ organization(login:"acme"){ name } }`)
	b, _ := io.ReadAll(ok.Body)
	ok.Body.Close()
	if ok.StatusCode != http.StatusOK {
		t.Fatalf("organization{name} must stay allowed at base read, got %d: %s", ok.StatusCode, string(b))
	}
}

// Round-20 MEDIUM: GraphQL repository{deployKeys} must be gated on the "keys" resource (a keys="none"
// carve-out denies it at the front gate), matching the REST GET /repos/{o}/{r}/keys deny.
func TestSec_R20_GraphQLDeployKeysDeny(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{{
			Name: "acme/secret", Access: policy.AccessRead,
			Permissions: map[string]policy.Access{"keys": policy.AccessNone},
		}},
	}
	h := r15Handler(t, pol, "http://127.0.0.1:0") // never forwarded — front-gate deny
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	resp := postGQL(t, srv.URL, `{ repository(owner:"acme",name:"secret"){ deployKeys(first:50){ nodes{ id title key readOnly } } } }`)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("repository{deployKeys} under keys=none must be 403, got %d", resp.StatusCode)
	}
}

// Round-20 MEDIUM: a WRITE response that echoes a foreign-repo head.repo (a fork-originated PR) must
// have that foreign repo scrubbed when denied, just like the GET path — the response-isolation block
// was GET/HEAD-only.
func TestSec_R20_WriteResponseCrossRefScrub(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{{
			Name: "acme/app", Access: policy.AccessReadWrite,
			Permissions: map[string]policy.Access{"pulls": policy.AccessReadWrite},
		}},
	}
	prBody := `{"title":"PR_TITLE","number":42,` +
		`"head":{"ref":"f","repo":{"full_name":"secretteam/fork","private":true,"clone_url":"https://x/secretteam/fork.git"}},` +
		`"base":{"ref":"main","repo":{"full_name":"acme/app"}}}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, prBody)
	}))
	t.Cleanup(upstream.Close)
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/repos/acme/app/pulls/42", strings.NewReader(`{"title":"x"}`))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(b)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorized PR edit expected 200, got %d: %s", resp.StatusCode, s)
	}
	if strings.Contains(s, "secretteam/fork") || strings.Contains(s, "secretteam") {
		t.Fatalf("write response leaked denied fork head.repo: %s", s)
	}
	if !strings.Contains(s, "PR_TITLE") || !strings.Contains(s, "acme/app") {
		t.Fatalf("write response over-scrubbed (lost the authorized PR/base): %s", s)
	}
}

// Round-20 MEDIUM: GET /orgs/{org}/attestations/repositories returns a bare {id,name} repo array
// qualified by the path org; denied private repos in the org must be dropped (name/existence leak).
func TestSec_R20_AttestationsRepoNamesRedacted(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org:      []policy.OrgRule{{Name: "acme", Access: policy.AccessRead}},
		Repo:     []policy.RepoRule{{Name: "acme/secretproj", Access: policy.AccessNone}},
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `[{"id":1,"name":"publicthing"},{"id":2,"name":"secretproj"}]`)
	}))
	t.Cleanup(upstream.Close)
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/orgs/acme/attestations/repositories")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(b)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, s)
	}
	if strings.Contains(s, "secretproj") {
		t.Fatalf("denied private repo name leaked via attestations feed: %s", s)
	}
	if !strings.Contains(s, "publicthing") {
		t.Fatalf("allowed repo name wrongly dropped: %s", s)
	}
}

// Round-20 MEDIUM/LOW: response headers must strip Github-Authentication-Token-Expiration (custodian
// lifecycle) and the request must NOT forward the client Cookie header upstream.
func TestSec_R20_HeaderHygiene(t *testing.T) {
	var gotCookie string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		w.Header().Set("Github-Authentication-Token-Expiration", "2026-06-06 18:00:00 UTC")
		w.Header().Set("ETag", `"keepme"`)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"login":"x"}`)
	}))
	t.Cleanup(upstream.Close)
	pol := &policy.Policy{Defaults: policy.Defaults{Mode: policy.ModeAllow}}
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/repos/o/r/pulls/1", nil)
	req.Header.Set("Cookie", "bgh_grant=secret.value; other=1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if v := resp.Header.Get("Github-Authentication-Token-Expiration"); v != "" {
		t.Fatalf("custodian token-expiration header leaked to client: %q", v)
	}
	if resp.Header.Get("ETag") == "" {
		t.Fatalf("benign ETag header wrongly stripped")
	}
	if gotCookie != "" {
		t.Fatalf("client Cookie header forwarded upstream: %q", gotCookie)
	}
}
