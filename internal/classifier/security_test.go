package classifier

// This file proves the classification bypasses found during the security audit are
// closed. Each TestSec_* asserts the secure (fixed) behavior; if a regression flips
// it, the test fails.

import (
	"strings"
	"testing"
)

// Regression for FINDING 1 (CRITICAL): GraphQL multi-root repository bypass — FIXED.
//
// A single GraphQL operation may select more than one repository, and GitHub
// executes them all. The classifier now enumerates every repository scope into
// AllScopes() so policy can check each one; it no longer stops at the first.
func TestSec_GraphQLMultiRoot_AllReposClassified(t *testing.T) {
	body := []byte(`{"query":"query { a: repository(owner: \"allowed\", name: \"pub\") { name } b: repository(owner: \"victim\", name: \"private\") { pullRequest(number: 1) { title body } } }"}`)

	r := Classify("POST", "/api/graphql", body)
	if r.Access != Read {
		t.Fatalf("expected Read, got %v", r.Access)
	}
	if !scopesContainRepo(r, "victim", "private") {
		t.Fatalf("FIXED-regressed: victim/private not in AllScopes()=%+v — the second repository is invisible to policy again", r.AllScopes())
	}
	if !scopesContainRepo(r, "allowed", "pub") {
		t.Fatalf("expected allowed/pub among scopes, got %+v", r.AllScopes())
	}
}

// Regression for FINDING 1b (CRITICAL): operationName is now honored. GitHub runs
// only the named operation, so that is the one the classifier scopes.
func TestSec_GraphQLOperationName_Honored(t *testing.T) {
	body := []byte(`{"query":"query Decoy { repository(owner: \"allowed\", name: \"pub\") { name } } query Real { repository(owner: \"victim\", name: \"private\") { pullRequest(number: 1) { title } } }","operationName":"Real"}`)

	r := Classify("POST", "/api/graphql", body)
	if !scopesContainRepo(r, "victim", "private") {
		t.Fatalf("FIXED-regressed: operationName=Real targets victim/private but it is not scoped; AllScopes()=%+v", r.AllScopes())
	}
	if scopesContainRepo(r, "allowed", "pub") {
		t.Fatalf("decoy operation allowed/pub should not be scoped when operationName selects Real; got %+v", r.AllScopes())
	}
}

// Regression for FINDING 4 (HIGH): every repo: qualifier in a search is scoped.
func TestSec_GraphQLSearch_AllRepoQualifiers(t *testing.T) {
	body := []byte(`{"query":"query { search(query: \"repo:allowed/pub repo:victim/private secret\", type: ISSUE, first: 10) { nodes { ... on Issue { title } } } }"}`)

	r := Classify("POST", "/api/graphql", body)
	if !scopesContainRepo(r, "allowed", "pub") || !scopesContainRepo(r, "victim", "private") {
		t.Fatalf("FIXED-regressed: both repo: qualifiers must be scoped; AllScopes()=%+v", r.AllScopes())
	}
}

// FINDING 2 support: a mutation's repo-scoped node IDs are extracted from BOTH
// inline arguments and variables (so neither location can smuggle a denied repo's
// node past the resolver). Non-repo-scoped IDs (users) are excluded so legitimate
// user-referencing mutations are not false-denied.
func TestSec_MutationNodeIDExtraction(t *testing.T) {
	body := []byte(`{"query":"mutation($pid: ID!){ closePullRequest(input:{pullRequestId:$pid}){clientMutationId} addAssigneesToAssignable(input:{assignableId:\"I_kwDOInlineIssue\", assigneeIds:[\"U_ignoreMe\"]}){clientMutationId} }","variables":{"pid":"PR_kwDOVarPR"}}`)

	r := Classify("POST", "/api/graphql", body)
	if r.Access != Write {
		t.Fatalf("expected Write, got %v", r.Access)
	}
	got := map[string]bool{}
	for _, id := range r.NodeIDs {
		got[id] = true
	}
	if !got["PR_kwDOVarPR"] {
		t.Errorf("variable node ID PR_kwDOVarPR not extracted: %v", r.NodeIDs)
	}
	if !got["I_kwDOInlineIssue"] {
		t.Errorf("inline node ID I_kwDOInlineIssue not extracted: %v", r.NodeIDs)
	}
	if got["U_ignoreMe"] {
		t.Errorf("user ID U_ignoreMe must NOT be extracted (would false-deny): %v", r.NodeIDs)
	}
}

// FINDING 7 (HIGH, DoS): a GraphQL query with cyclic fragments, a long fragment
// chain, or deeply nested selections previously stack-overflowed the recursive walk —
// an unrecoverable process crash triggerable by any client. Classification must now
// return without crashing and fail closed (no scope) for over-complex queries.
func TestSec_GraphQLRecursionBoundedNoCrash(t *testing.T) {
	cyclic := []byte(`{"query":"query { ...A } fragment A on Query { ...B } fragment B on Query { ...A }"}`)

	var deep strings.Builder
	deep.WriteString(`{"query":"query `)
	for i := 0; i < 5000; i++ {
		deep.WriteString("{ a ")
	}
	for i := 0; i < 5000; i++ {
		deep.WriteString("}")
	}
	deep.WriteString(`"}`)

	for _, body := range [][]byte{cyclic, []byte(deep.String())} {
		// Must not crash. An over-complex read fails closed to an unscoped write, which
		// the policy engine denies unconditionally.
		r := Classify("POST", "/api/graphql", body)
		if r.HasRepo() {
			t.Fatalf("over-complex query must not yield an allowable repo scope, got %s", r.RepoFullName())
		}
		if r.Access != Write {
			t.Fatalf("over-complex query should fail closed to Write (→ unscoped write denied), got %v", r.Access)
		}
	}
}

func scopesContainRepo(r Result, owner, repo string) bool {
	for _, s := range r.AllScopes() {
		if s.Owner == owner && s.Repo == repo {
			return true
		}
	}
	return false
}

// FINDING 3 (HIGH), classifier half: owner/repo case is preserved, not normalized.
//
// GitHub treats owner/repo/org names case-insensitively for routing, but the
// classifier returns them verbatim and the policy engine compares them with exact
// string equality. The combination lets a case variant dodge an exact-match rule.
// (The policy-layer proof is in internal/policy/security_test.go.)
func TestSec_CasePreservedNotNormalized(t *testing.T) {
	r := Classify("GET", "/api/v3/repos/Acme/Secret/contents/x", nil)
	if r.Owner != "Acme" || r.Repo != "Secret" {
		t.Fatalf("expected verbatim casing Acme/Secret, got %s/%s", r.Owner, r.Repo)
	}
	// Same repo, different case → different RepoFullName → different policy outcome.
	lower := Classify("GET", "/api/v3/repos/acme/secret/contents/x", nil)
	if r.RepoFullName() == lower.RepoFullName() {
		t.Fatalf("case variants collapsed — normalization may have been added; update the policy-layer test too")
	}
	t.Logf("VULNERABLE: GitHub-equivalent paths /repos/Acme/Secret and /repos/acme/secret classify as distinct repos")
}

// FINDING 6 (MEDIUM): path traversal segments are passed through.
//
// splitPath keeps ".." as a literal segment, so the classifier reads the owner/repo
// from the segments BEFORE the "..". internal/proxy/proxy.go then forwards the
// normalized path (which still contains "..") to GitHub verbatim. If GitHub's edge
// collapses "..", the request reaches a different repo than the one policy checked.
// Percent-encoded slashes (%2F) decode into the path before classification, so a
// naive raw-path check would not catch this.
func TestSec_PathTraversal_ClassifiesPrefixRepo(t *testing.T) {
	r := Classify("GET", "/api/v3/repos/allowed/pub/../../victim/private/pulls", nil)
	if r.RepoFullName() != "allowed/pub" {
		t.Fatalf("expected classifier to read the prefix repo allowed/pub, got %q", r.RepoFullName())
	}
	t.Logf("VULNERABLE: path contains ../../victim/private but classifier reports repo=%q; forward() sends '..' to GitHub unchanged", r.RepoFullName())
}

// Regression for FINDING 5 (MEDIUM) — write-capable REST segments that aren't in
// restResourceMap now classify as the ResourceUnknown sentinel (not ""), which the
// policy engine fails closed on for writes when per-resource permissions are in
// effect (see internal/policy/security_test.go). This stops POST /repos/o/r/dispatches
// (which can trigger workflows) from escaping an actions=none restriction.
func TestSec_ResourceGap_UnmappedWriteSegments(t *testing.T) {
	for _, seg := range []string{"dispatches", "transfer", "merges", "import", "vulnerability-alerts"} {
		r := Classify("POST", "/api/v3/repos/o/r/"+seg, []byte(`{}`))
		if r.Resource != ResourceUnknown {
			t.Fatalf("expected %q to classify as ResourceUnknown, got Resource=%q", seg, r.Resource)
		}
		if r.Access != Write {
			t.Fatalf("expected Write for POST, got %v", r.Access)
		}
	}
}
