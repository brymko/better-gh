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

// Round-18 A (HIGH): a repo-owned CONCRETE type that does NOT implement Node (Submodule→contents)
// must be redacted under a per-resource `none`, reached by GraphQL navigation. The proxy augments
// the outgoing query to request a type marker on the Submodule nodes (as GitHub then echoes), so
// the filter attributes them to the enclosing repository and enforces FilterResource("Submodule")
// ("contents"). Before round-18 these types got NO marker and streamed back unredacted.
func TestSec_R18_GraphQLNonNodeRepoOwnedRedacted(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	// Faithful upstream: GitHub echoes the proxy-injected `bghRepoTypeZ9: __typename` markers,
	// including the one augment now injects inside submodules{nodes}.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"repository":{`+
			`"bghRepoTagZ9":"victim/private","bghRepoTypeZ9":"Repository",`+
			`"submodules":{"nodes":[`+
			`{"path":"vendor/secret","gitUrl":"git@host:victim/superprivate.git","subprojectCommitOid":"deadbeef","bghRepoTypeZ9":"Submodule"}`+
			`]}}}}`)
	}))
	t.Cleanup(upstream.Close)

	body := `{"query":"query { repository(owner:\"victim\",name:\"private\") { submodules(first:50){ nodes { path gitUrl subprojectCommitOid } } } }"}`

	run := func(contents policy.Access) string {
		pol := &policy.Policy{
			Defaults: policy.Defaults{Mode: policy.ModeDeny},
			Repo: []policy.RepoRule{{
				Name: "victim/private", Access: policy.AccessRead,
				Permissions: map[string]policy.Access{"contents": contents},
			}},
		}
		h := &Handler{
			GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
			Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol,
			UpstreamURL: upstream.URL, GQLFilter: sch,
		}
		srv := httptest.NewServer(h)
		t.Cleanup(srv.Close)
		resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return string(out)
	}

	// contents=none → the submodule (a contents object) must be redacted.
	if s := run(policy.AccessNone); strings.Contains(s, "superprivate") || strings.Contains(s, "vendor/secret") {
		t.Fatalf("contents=none must redact Submodule, leaked: %s", s)
	}
	// contents=read → not over-redacted.
	if s := run(policy.AccessRead); !strings.Contains(s, "superprivate") {
		t.Fatalf("contents=read must keep Submodule, got: %s", s)
	}
}

// Round-18 D (HIGH): the REST enumeration keep-gate must consult the endpoint's per-resource key,
// not only metadata. A repo with base=read but issues="none" must NOT surface its issues in the
// org-wide /orgs/{org}/issues feed (the direct /repos/{o}/{r}/issues path is 403), and an allowed
// repo's issues must still pass.
func TestSec_R18_RESTEnumPerResourceDeny(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org:      []policy.OrgRule{{Name: "acme", Access: policy.AccessRead}},
		Repo: []policy.RepoRule{{
			Name: "acme/crown", Access: policy.AccessRead,
			Permissions: map[string]policy.Access{"issues": policy.AccessNone},
		}},
	}
	feed := `[{"title":"SECRET_ISSUE","body":"x","repository":{"full_name":"acme/crown"}},` +
		`{"title":"OK_ISSUE","body":"y","repository":{"full_name":"acme/open"}}]`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, feed)
	}))
	t.Cleanup(upstream.Close)
	h := r15Handler(t, pol, upstream.URL)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	// Direct per-repo path proves intent: issues denied → 403.
	if resp, err := http.Get(srv.URL + "/repos/acme/crown/issues"); err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("direct /repos/acme/crown/issues must be 403, got %d", resp.StatusCode)
		}
	} else {
		t.Fatal(err)
	}

	// Enumeration feed must drop the issues=none repo's entry, keep the allowed one.
	resp, err := http.Get(srv.URL + "/orgs/acme/issues")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(b)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/orgs/acme/issues expected 200, got %d: %s", resp.StatusCode, s)
	}
	if strings.Contains(s, "SECRET_ISSUE") || strings.Contains(s, "acme/crown") {
		t.Fatalf("issues=none repo leaked via enumeration: %s", s)
	}
	if !strings.Contains(s, "OK_ISSUE") {
		t.Fatalf("allowed repo's issue wrongly dropped: %s", s)
	}
}

// Round-18 F (MEDIUM): the response-header strip must drop X-GitHub-SSO (custodian's SSO-org reach)
// and Set-Cookie, while still forwarding benign headers.
func TestSec_R18_SSOAndCookieHeadersStripped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-GitHub-SSO", "partial-results; organizations=21955855,20582480")
		w.Header().Set("Set-Cookie", "logged_in=yes; Path=/")
		w.Header().Set("X-RateLimit-Remaining", "4999") // benign — must pass
		io.WriteString(w, `[]`)
	}))
	t.Cleanup(upstream.Close)
	pol := &policy.Policy{Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{{Name: "o/r", Access: policy.AccessRead}}}
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol, UpstreamURL: upstream.URL,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/repos/o/r/pulls")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if v := resp.Header.Get("X-GitHub-SSO"); v != "" {
		t.Errorf("X-GitHub-SSO leaked custodian SSO-org reach: %q", v)
	}
	if v := resp.Header.Get("Set-Cookie"); v != "" {
		t.Errorf("Set-Cookie forwarded to client: %q", v)
	}
	if resp.Header.Get("X-Ratelimit-Remaining") != "4999" {
		t.Errorf("benign header X-RateLimit-Remaining should still be forwarded")
	}
}

// Round-18 B safety: the fragment-fanout DoS fix changed cyclic-fragment classification from a
// denied Write to a no-scope Read; the proxy must STILL deny a cyclic (GraphQL-invalid) query —
// augment rejects it, so the "could not be typed" fail-closed gate fires even under ModeAllow.
func TestSec_R18_CyclicFragmentStillDenied(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{}}`)
	}))
	t.Cleanup(upstream.Close)
	h := &Handler{
		GithubToken: "tok", Mode: SocketMode,
		SocketPolicy: &policy.Policy{Defaults: policy.Defaults{Mode: policy.ModeAllow}},
		Audit:        audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client:       upstream.Client(), GQLFilter: sch, UpstreamURL: upstream.URL,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	body := `{"query":"query { ...A } fragment A on Query { ...B } fragment B on Query { ...A }"}`
	resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("cyclic fragment under ModeAllow must be denied, got %d: %s", resp.StatusCode, b)
	}
}
