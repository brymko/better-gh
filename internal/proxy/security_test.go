package proxy

// End-to-end exploit proofs against the real proxy pipeline (auth → classify →
// policy → forward) using the shared setup() harness. The harness token policy is:
//   default deny; org allowed-org=read; repo allowed-org/rw-repo=read-write;
//   repo blocked-org/secret=none.
// A 403 means the proxy blocked the request; any forwarded request returns the mock
// GitHub status (200/201). These tests assert the bypass currently SUCCEEDS, i.e.
// the proxy forwards requests it should have blocked.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"better-gh/internal/audit"
	"better-gh/internal/gqlfilter"
	"better-gh/internal/nodecache"
	"better-gh/internal/policy"
	"better-gh/internal/store"
)

// FINDING 9 (CRITICAL) — schema-aware response filter: a GraphQL read that navigates
// from an allowed repo to a denied repo is forwarded, but the proxy redacts every
// repo-scoped object whose repository the policy denies. Here the upstream returns a
// response containing both repos (with the injected markers); the denied repo's content
// must be stripped, the allowed repo's kept, and the markers removed.
func TestSec_GraphQLFilterRedactsDeniedRepoFromResponse(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"repository":{"bghRepoTagZ9":"allowed-org/rw-repo","name":"rw-repo","owner":{"repositories":{"nodes":[`+
			`{"bghRepoTagZ9":"allowed-org/rw-repo","name":"rw-repo"},`+
			`{"bghRepoTagZ9":"blocked-org/secret","name":"secret","issues":{"nodes":[`+
			`{"bghRepoTagZ9":{"nameWithOwner":"blocked-org/secret"},"body":"TOPSECRET_LEAK"}]}}]}}}}}`)
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

	body := `{"query":"query{repository(owner:\"allowed-org\",name:\"rw-repo\"){name owner{repositories(first:50){nodes{name issues(first:5){nodes{body}}}}}}}"}`
	resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	s := string(out)
	if strings.Contains(s, "TOPSECRET_LEAK") || strings.Contains(s, "secret") {
		t.Fatalf("denied repo not redacted: %s", s)
	}
	if !strings.Contains(s, "rw-repo") {
		t.Fatalf("allowed repo data was lost: %s", s)
	}
	if strings.Contains(s, "bghRepoTagZ9") {
		t.Fatalf("injected marker leaked to client: %s", s)
	}
}

func mustStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir() + "/tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// recordingHandler wires a proxy.Handler to an upstream that records the headers it
// receives, so tests can assert what was (and wasn't) forwarded.
func recordingProxy(t *testing.T, pol policy.Policy) (*httptest.Server, string, *http.Header, *int32) {
	t.Helper()
	var got http.Header
	var resolveCalls int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "graphql") {
			atomic.AddInt32(&resolveCalls, 1)
		}
		got = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
	}))
	t.Cleanup(upstream.Close)

	s, err := store.Open(t.TempDir() + "/tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	_, secret, err := s.Create("rec", pol)
	if err != nil {
		t.Fatal(err)
	}
	nc := nodecache.New(time.Minute)
	t.Cleanup(nc.Stop)
	h := &Handler{
		GithubToken: "real-secret-token",
		Store:       s,
		Audit:       audit.NewLogger(t.TempDir() + "/audit.jsonl"),
		Client:      &http.Client{},
		Mode:        GHEMode,
		UpstreamURL: upstream.URL,
		NodeCache:   nc,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, secret, &got, &resolveCalls
}

// Fix for forward() clobbering client headers: the client's Accept (media-type
// negotiation) and conditional-request headers are forwarded, while its Authorization
// is dropped and replaced with the real token (never leaked, never passed through).
func TestSec_ClientHeadersForwarded(t *testing.T) {
	pol := policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo:     []policy.RepoRule{{Name: "o/r", Access: policy.AccessRead}},
	}
	srv, secret, got, _ := recordingProxy(t, pol)

	req, _ := http.NewRequest("GET", srv.URL+"/api/v3/repos/o/r/pulls/1", nil)
	req.Header.Set("Authorization", "token "+secret)
	req.Header.Set("Accept", "application/vnd.github.v3.diff")
	req.Header.Set("If-None-Match", `"etag123"`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if a := got.Get("Accept"); a != "application/vnd.github.v3.diff" {
		t.Errorf("client Accept not forwarded, upstream saw %q", a)
	}
	if got.Get("If-None-Match") != `"etag123"` {
		t.Errorf("conditional-request header not forwarded")
	}
	if auth := got.Get("Authorization"); auth != "token real-secret-token" {
		t.Errorf("upstream Authorization should be the real token, got %q", auth)
	}
	if strings.Contains(got.Get("Authorization"), secret) {
		t.Errorf("client proxy token leaked upstream")
	}
}

// Fix for resolver rate-limit burn: a token that can never write must not trigger the
// upstream node-resolution call.
func TestSec_NoResolveForNonWritingToken(t *testing.T) {
	pol := policy.Policy{Defaults: policy.Defaults{Mode: policy.ModeDeny}} // all deny → no write possible
	srv, secret, _, resolveCalls := recordingProxy(t, pol)

	body := `{"query":"mutation($id: ID!){ closePullRequest(input:{pullRequestId:$id}){ clientMutationId } }","variables":{"id":"PR_kwDOsomething"}}`
	req, _ := http.NewRequest("POST", srv.URL+"/api/graphql", strings.NewReader(body))
	req.Header.Set("Authorization", "token "+secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("mutation under all-deny policy should be denied, got %d", resp.StatusCode)
	}
	if n := atomic.LoadInt32(resolveCalls); n != 0 {
		t.Fatalf("non-writing token must not trigger upstream resolves, got %d", n)
	}
}

// Regression for FINDING 5 (MEDIUM) e2e: with a read-write base grant plus per-resource
// permissions, a write to an unmapped sibling endpoint (POST /dispatches, which can
// trigger workflows) is denied instead of inheriting the base grant — so it cannot
// escape the actions=none restriction.
func TestSec_E2E_UnmappedWriteFailsClosed(t *testing.T) {
	env := setup(t)
	pol := policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{{
			Name:        "allowed-org/rw-repo",
			Access:      policy.AccessReadWrite,
			Permissions: map[string]policy.Access{"actions": policy.AccessNone},
		}},
	}
	_, secret, err := env.store.Create("perm-rw-token", pol)
	if err != nil {
		t.Fatal(err)
	}
	client := gheClient(secret)

	// Unmapped write endpoint → denied (fails closed).
	resp, err := client.Post(env.gheServer.URL+"/api/v3/repos/allowed-org/rw-repo/dispatches", "application/json", strings.NewReader(`{"event_type":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unmapped write /dispatches should fail closed under per-resource policy, got %d", resp.StatusCode)
	}

	// Control: a mapped, permitted write (pulls falls back to read-write base) still works.
	resp2, err := client.Post(env.gheServer.URL+"/api/v3/repos/allowed-org/rw-repo/pulls", "application/json", strings.NewReader(`{"title":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusForbidden {
		t.Fatalf("mapped write /pulls should be allowed under base read-write, got 403")
	}
}

// Regression for FINDING 6 (MEDIUM): a path containing ".." (or %2F-smuggled "..")
// is rejected before classification, so it can never be forwarded to GitHub.
func TestSec_E2E_PathTraversalRejected(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret)

	for _, p := range []string{
		"/api/v3/repos/allowed-org/rw-repo/../../blocked-org/secret/pulls",
		"/api/v3/repos/allowed-org/rw-repo/%2e%2e/%2e%2e/blocked-org/secret/pulls",
		"/api/v3/repos/allowed-org/rw-repo%2f..%2f..%2fblocked-org/secret/pulls",
	} {
		resp, err := client.Get(env.gheServer.URL + p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 for traversal path %q, got %d", p, resp.StatusCode)
		}
	}
}

// FINDING 8 (Medium) e2e: under default=allow, a node(id:) read of a blocked repo's
// object must be denied. Before the fix it extracted no scope and fell through to the
// permissive default, bypassing the [[repo]] none block.
func TestSec_E2E_NodeIDReadBlockedRepoDeniedUnderAllow(t *testing.T) {
	env := setup(t)
	pol := policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeAllow},
		Repo:     []policy.RepoRule{{Name: "blocked-org/secret", Access: policy.AccessNone}},
	}
	_, secret, err := env.store.Create("allow-default-token", pol)
	if err != nil {
		t.Fatal(err)
	}
	client := gheClient(secret)

	body := `{"query":"query { node(id: \"PR_BlockedSecretNode\") { ... on PullRequest { title body } } }"}`
	resp, err := client.Post(env.gheServer.URL+"/api/graphql", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("node(id) read of a blocked repo must be denied under default=allow, got %d", resp.StatusCode)
	}
}

// A node(id:) read that resolves to a readable repo works (no over-denial), and an
// unresolvable node fails closed.
func TestSec_E2E_NodeIDReadResolution(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret) // default deny; org allowed-org=read

	ok := `{"query":"query { node(id: \"PR_AllowedRwNode\") { ... on PullRequest { title } } }"}`
	resp, err := client.Post(env.gheServer.URL+"/api/graphql", "application/json", strings.NewReader(ok))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("node(id) read of an allowed repo should succeed, got 403")
	}

	bad := `{"query":"query { node(id: \"PR_kwDONeverResolves\") { ... on PullRequest { title } } }"}`
	resp2, err := client.Post(env.gheServer.URL+"/api/graphql", "application/json", strings.NewReader(bad))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("unresolvable node(id) read should fail closed, got %d", resp2.StatusCode)
	}
}

// Baseline control: a single-repo GraphQL read of the blocked repo is correctly
// denied. This is the behavior the multi-root bypass below evades.
func TestSec_E2E_GraphQLSingleBlockedRepoDenied(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret)
	body := `{"query":"query { repository(owner: \"blocked-org\", name: \"secret\") { pullRequest(number: 1) { title } } }"}`
	resp, err := client.Post(env.gheServer.URL+"/api/graphql", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected single-repo read of blocked-org/secret to be denied, got %d", resp.StatusCode)
	}
}

// Regression for FINDING 1 (CRITICAL) e2e — FIXED: a multi-root GraphQL query that
// names the blocked repo as its second field is now denied, because the classifier
// scopes every repository and policy rejects blocked-org/secret.
func TestSec_E2E_GraphQLMultiRootReadBypass(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret)

	body := `{"query":"query { a: repository(owner: \"allowed-org\", name: \"rw-repo\") { name } b: repository(owner: \"blocked-org\", name: \"secret\") { pullRequest(number: 1) { id title } } }"}`
	resp, err := client.Post(env.gheServer.URL+"/api/graphql", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("FIXED-regressed: multi-root query touching blocked-org/secret should be denied (403), got %d", resp.StatusCode)
	}
}

// Control: a multi-root query where every repo is allowed still succeeds.
func TestSec_E2E_GraphQLMultiRootAllAllowed(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret)
	body := `{"query":"query { a: repository(owner: \"allowed-org\", name: \"rw-repo\") { name } b: repository(owner: \"allowed-org\", name: \"rw-repo\") { issues(first:1){ nodes { title } } } }"}`
	resp, err := client.Post(env.gheServer.URL+"/api/graphql", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("multi-root query with only allowed repos should pass, got 403")
	}
}

// Regression for FINDING 2 (CRITICAL) e2e — the mixed inline+variable bypass is
// closed. A mutation supplies one node ID via a variable (resolves to the client's
// WRITABLE repo) and a second inline node ID (resolves to a DENIED repo). Because the
// classifier extracts node IDs from inline arguments too, both are resolved and
// policy-checked, so the request is denied on the denied repo.
func TestSec_E2E_MutationMixedInlineAndVariableNodes(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret)

	body := `{"query":"mutation($id: ID!){ a: closePullRequest(input:{pullRequestId:$id}){ clientMutationId } b: closePullRequest(input:{pullRequestId:\"PR_BlockedSecretNode\"}){ clientMutationId } }","variables":{"id":"PR_AllowedRwNode"}}`
	resp, err := client.Post(env.gheServer.URL+"/api/graphql", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("mutation touching a denied repo via an inline node ID must be denied, got %d", resp.StatusCode)
	}
}

// Control: a mutation on an unresolvable node (GitHub returns null) fails closed.
func TestSec_E2E_MutationUnknownNodeDenied(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret)

	mut := `{"query":"mutation($id: ID!){ closePullRequest(input:{pullRequestId:$id}){ clientMutationId } }","variables":{"id":"PR_kwDONeverSeenBefore"}}`
	resp, err := client.Post(env.gheServer.URL+"/api/graphql", "application/json", strings.NewReader(mut))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected unseen-node mutation to be denied (unscoped write), got %d", resp.StatusCode)
	}
}
