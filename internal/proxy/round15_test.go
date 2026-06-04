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

// r15Handler builds a Handler wired like production (loaded schema + node cache) against a mock
// upstream, in socket mode with the given policy.
func r15Handler(t *testing.T, pol *policy.Policy, upstreamURL string) *Handler {
	t.Helper()
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	nc := nodecache.New(time.Minute)
	t.Cleanup(nc.Stop)
	return &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol,
		UpstreamURL: upstreamURL, GQLFilter: sch, NodeCache: nc,
	}
}

func postGQL(t *testing.T, srvURL, query string) *http.Response {
	t.Helper()
	resp, err := http.Post(srvURL+"/graphql", "application/json", strings.NewReader(`{"query":`+jsonString(query)+`}`))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func jsonString(s string) string {
	b := strings.Builder{}
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// round-15 CRITICAL: a multi-root mutation with an allowed plain-string target and a DENIED
// block-string target must be denied (the block-string target is now scoped + policy-checked), and
// the mutation must NOT reach upstream.
func TestSec_R15_BlockStringCrossRepoWriteDenied(t *testing.T) {
	forwarded := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded = true
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{}}`)
	}))
	t.Cleanup(upstream.Close)

	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{
			{Name: "o/rw", Access: policy.AccessReadWrite},
			// o/secret has no rule → denied under mode=deny.
		},
	}
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp := postGQL(t, srv.URL, `mutation {
	  a: createCommitOnBranch(input:{branch:{repositoryNameWithOwner:"o/rw",branchName:"main"},message:{headline:"x"},expectedHeadOid:"d"}){commit{url}}
	  b: createCommitOnBranch(input:{branch:{repositoryNameWithOwner:"""o/secret""",branchName:"main"},message:{headline:"y"},expectedHeadOid:"d"}){commit{url}}
	}`)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("block-string denied target must be 403, got %d", resp.StatusCode)
	}
	if forwarded {
		t.Fatal("denied multi-root mutation must NOT reach upstream")
	}
}

// round-15 HIGH: createCommitOnBranch (file-content write) must be denied under contents=none even
// when branches is writable, and allowed under contents=read-write.
func TestSec_R15_CreateCommitOnBranchIsContents(t *testing.T) {
	for _, tc := range []struct {
		name        string
		contents    policy.Access
		wantForward bool
		wantStatus  int
	}{
		{"contents-none-denied", policy.AccessNone, false, http.StatusForbidden},
		{"contents-rw-allowed", policy.AccessReadWrite, true, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forwarded := false
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded = true
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{"data":{"createCommitOnBranch":{"commit":{"url":"u"}}}}`)
			}))
			t.Cleanup(upstream.Close)
			pol := &policy.Policy{
				Defaults: policy.Defaults{Mode: policy.ModeDeny},
				Repo: []policy.RepoRule{{
					Name: "o/app", Access: policy.AccessNone,
					Permissions: map[string]policy.Access{"branches": policy.AccessReadWrite, "contents": tc.contents},
				}},
			}
			h := r15Handler(t, pol, upstream.URL)
			srv := httptest.NewServer(h)
			t.Cleanup(srv.Close)
			resp := postGQL(t, srv.URL, `mutation{createCommitOnBranch(input:{branch:{repositoryNameWithOwner:"o/app",branchName:"main"},message:{headline:"x"},expectedHeadOid:"d"}){commit{url}}}`)
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != tc.wantStatus || forwarded != tc.wantForward {
				t.Fatalf("contents=%v: want status %d forward %v, got %d forward %v", tc.contents, tc.wantStatus, tc.wantForward, resp.StatusCode, forwarded)
			}
		})
	}
}

// round-15 HIGH: the Git Data API must obey per-resource branches/contents/commits restrictions.
func TestSec_R15_GitDataAPIPerResource(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{{
			Name: "o/app", Access: policy.AccessReadWrite,
			Permissions: map[string]policy.Access{"branches": policy.AccessNone, "contents": policy.AccessNone, "commits": policy.AccessReadWrite},
		}},
	}
	for _, tc := range []struct {
		method, path string
		wantForward  bool
	}{
		{"POST", "/repos/o/app/git/refs", false},      // create branch → branches=none → denied
		{"GET", "/repos/o/app/git/blobs/abc", false},  // raw file bytes → contents=none → denied
		{"GET", "/repos/o/app/git/trees/abc", false},  // tree listing → contents=none → denied
		{"GET", "/repos/o/app/git/commits/abc", true}, // commits=read-write → allowed
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			forwarded := false
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				forwarded = true
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, `{}`)
			}))
			t.Cleanup(upstream.Close)
			h := r15Handler(t, pol, upstream.URL)
			srv := httptest.NewServer(h)
			t.Cleanup(srv.Close)
			req, _ := http.NewRequest(tc.method, srv.URL+tc.path, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if forwarded != tc.wantForward {
				t.Fatalf("%s %s: want forwarded=%v, got %v (status %d)", tc.method, tc.path, tc.wantForward, forwarded, resp.StatusCode)
			}
		})
	}
}

// round-15 HIGH: a node-ID READ that piggybacks on an unscoped primary scope (viewer/user) must NOT
// drop the user-category check — the custodian's viewer{} identity must stay denied.
func TestSec_R15_ViewerNodeIDCollapseDenied(t *testing.T) {
	forwarded := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(body), "nodes(ids") {
			io.WriteString(w, `{"data":{"nodes":[{"__typename":"Issue","repository":{"nameWithOwner":"o/r"}}]}}`)
			return
		}
		forwarded = true
		io.WriteString(w, `{"data":{"viewer":{"login":"CUSTODIAN_SECRET","email":"boss@corp"}}}`)
	}))
	t.Cleanup(upstream.Close)

	// reads o/r, but the `user` unscoped category is NOT granted.
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo:     []policy.RepoRule{{Name: "o/r", Access: policy.AccessRead}},
	}
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp := postGQL(t, srv.URL, `query{viewer{login email} node(id:"I_kwDOABC123"){__typename}}`)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer+node mixed read must be 403 (user denied), got %d body=%s", resp.StatusCode, b)
	}
	if forwarded || strings.Contains(string(b), "CUSTODIAN_SECRET") {
		t.Fatalf("custodian viewer identity must not leak: forwarded=%v body=%s", forwarded, b)
	}
}

// round-15 MEDIUM: a resolved node whose runtime __typename the embedded schema doesn't recognize
// (live drift) must fail closed, not be treated as a constraint-free non-repo node.
func TestSec_R15_NodeDriftFailClosed(t *testing.T) {
	forwarded := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(body), "nodes(ids") {
			// carrier resolves to the allowed repo; the drift node returns an unknown type, no repo.
			io.WriteString(w, `{"data":{"nodes":[`+
				`{"__typename":"PullRequest","repository":{"nameWithOwner":"o/rw"}},`+
				`{"__typename":"NewlyAddedRepoScopedType"}]}}`)
			return
		}
		forwarded = true
		io.WriteString(w, `{"data":{}}`)
	}))
	t.Cleanup(upstream.Close)

	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo:     []policy.RepoRule{{Name: "o/rw", Access: policy.AccessReadWrite}},
	}
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	resp := postGQL(t, srv.URL, `mutation{a:addComment(input:{subjectId:"PR_kwDOcarrier1",body:"x"}){clientMutationId} b:addComment(input:{subjectId:"X_kwDOdrift2",body:"y"}){clientMutationId}}`)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("drift node must fail closed (403), got %d", resp.StatusCode)
	}
	if forwarded {
		t.Fatal("mutation with an unresolved drift node must NOT reach upstream")
	}
}

// round-15 HIGH/MEDIUM: REST enum endpoints must drop a per-resource-carve-out repo (access=none +
// a narrow grant), matching the direct path and the GraphQL container gate. CanReadAnything used to
// keep them, leaking alert/metadata data.
func TestSec_R15_RESTEnumPerResource(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny, Unscoped: map[string]policy.Access{"user": policy.AccessRead}},
		Org:      []policy.OrgRule{{Name: "acme", Access: policy.AccessRead}},
		Repo: []policy.RepoRule{{
			Name: "acme/crown", Access: policy.AccessNone,
			Permissions: map[string]policy.Access{"issues": policy.AccessRead},
		}},
	}
	for _, tc := range []struct {
		name, path, body, secret, keep string
	}{
		{
			"org-dependabot-alerts", "/orgs/acme/dependabot/alerts",
			`[{"repository":{"full_name":"acme/crown"},"security_advisory":{"ghsa_id":"CVE_CROWN_LEAK"}},{"repository":{"full_name":"acme/open"},"security_advisory":{"ghsa_id":"OK"}}]`,
			"CVE_CROWN_LEAK", "acme/open",
		},
		{
			"user-repos-metadata", "/user/repos",
			`[{"full_name":"acme/crown","description":"TOP_SECRET_DESC","private":true},{"full_name":"acme/open","description":"ok"}]`,
			"TOP_SECRET_DESC", "acme/open",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, tc.body)
			}))
			t.Cleanup(upstream.Close)
			h := r15Handler(t, pol, upstream.URL)
			srv := httptest.NewServer(h)
			t.Cleanup(srv.Close)
			resp, err := http.Get(srv.URL + tc.path)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			s := string(b)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s: expected 200, got %d (%s)", tc.path, resp.StatusCode, s)
			}
			if strings.Contains(s, tc.secret) || strings.Contains(s, "acme/crown") {
				t.Fatalf("%s: carve-out repo data leaked: %s", tc.path, s)
			}
			if !strings.Contains(s, tc.keep) {
				t.Fatalf("%s: allowed repo wrongly dropped: %s", tc.path, s)
			}
		})
	}
}

// round-15 MEDIUM: cross-ref repo metadata (fork parent, event forkee) of a denied repo must be
// scrubbed (nulled in place) while the surrounding object/row survives.
func TestSec_R15_RESTCrossRefScrub(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo:     []policy.RepoRule{{Name: "acme/fork", Access: policy.AccessRead}}, // victim/private denied
	}
	for _, tc := range []struct {
		name, path, body, secret string
	}{
		{
			"fork-parent", "/repos/acme/fork",
			`{"full_name":"acme/fork","parent":{"full_name":"victim/private","description":"PARENT_SECRET","private":true}}`,
			"PARENT_SECRET",
		},
		{
			"event-forkee", "/repos/acme/fork/events",
			`[{"type":"ForkEvent","repo":{"name":"acme/fork"},"payload":{"forkee":{"full_name":"victim/private","description":"FORKEE_SECRET","private":true}}}]`,
			"FORKEE_SECRET",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, tc.body)
			}))
			t.Cleanup(upstream.Close)
			h := r15Handler(t, pol, upstream.URL)
			srv := httptest.NewServer(h)
			t.Cleanup(srv.Close)
			resp, err := http.Get(srv.URL + tc.path)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			s := string(b)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s: expected 200, got %d (%s)", tc.path, resp.StatusCode, s)
			}
			if strings.Contains(s, tc.secret) || strings.Contains(s, "victim/private") {
				t.Fatalf("%s: denied cross-ref repo metadata leaked: %s", tc.path, s)
			}
			if !strings.Contains(s, "acme/fork") {
				t.Fatalf("%s: surrounding object should survive the scrub: %s", tc.path, s)
			}
		})
	}
}
