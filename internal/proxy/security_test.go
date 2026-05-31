package proxy

// End-to-end exploit proofs against the real proxy pipeline (auth → classify →
// policy → forward) using the shared setup() harness. The harness token policy is:
//   default deny; org allowed-org=read; repo allowed-org/rw-repo=read-write;
//   repo blocked-org/secret=none.
// A 403 means the proxy blocked the request; any forwarded request returns the mock
// GitHub status (200/201). These tests assert the bypass currently SUCCEEDS, i.e.
// the proxy forwards requests it should have blocked.

import (
	"net/http"
	"strings"
	"testing"

	"better-gh/internal/policy"
)

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
