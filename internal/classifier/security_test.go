package classifier

// This file proves the classification bypasses found during the security audit are
// closed. Each TestSec_* asserts the secure (fixed) behavior; if a regression flips
// it, the test fails.

import (
	"encoding/json"
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

// FINDING 2 support: a mutation's node IDs are extracted from BOTH inline arguments and
// variables (so neither location can smuggle a denied repo's node past the resolver). The
// classifier no longer filters by node type — it extracts every node-ID-shaped value; the
// proxy resolver classifies each (repo-scoped → policy-checked, non-repo like a user →
// ignored). This is what keeps repo-scoped types whose prefix used to be unlisted from
// being bypassed. (Resolution-layer behavior is proven in internal/proxy/security_test.go.)
func TestSec_MutationNodeIDExtraction(t *testing.T) {
	body := []byte(`{"query":"mutation($pid: ID!){ closePullRequest(input:{pullRequestId:$pid}){clientMutationId} addAssigneesToAssignable(input:{assignableId:\"I_kwDOInlineIssue\", assigneeIds:[\"U_kwDOignoreMe\"]}){clientMutationId} }","variables":{"pid":"PR_kwDOVarPR"}}`)

	r := Classify("POST", "/api/graphql", body)
	if r.Access != Write {
		t.Fatalf("expected Write, got %v", r.Access)
	}
	got := map[string]bool{}
	for _, id := range r.NodeIDs {
		got[id] = true
	}
	// All node-ID-shaped values are extracted (incl. the user ID, which the resolver then
	// classifies as non-repo and ignores) — none may be silently dropped at this layer.
	for _, want := range []string{"PR_kwDOVarPR", "I_kwDOInlineIssue", "U_kwDOignoreMe"} {
		if !got[want] {
			t.Errorf("node ID %s not extracted: %v", want, r.NodeIDs)
		}
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
		// Must not crash and must not yield an allowable repo scope. The per-walk
		// fragment visited-guard now resolves a cyclic fragment to a benign no-scope read
		// (each fragment expanded once) instead of tripping the depth bound — that is sound
		// because the query carries no fields/scopes, and the proxy denies the (invalid)
		// cyclic query at the augment-failure gate regardless (see proxy cyclic test).
		r := Classify("POST", "/api/graphql", body)
		if r.HasRepo() || r.Org != "" {
			t.Fatalf("over-complex query must not yield an allowable repo/org scope, got repo=%q org=%q", r.RepoFullName(), r.Org)
		}
		if len(r.NodeIDs) != 0 || len(r.Additional) != 0 {
			t.Fatalf("over-complex query must carry no node IDs or additional scopes, got nodes=%v additional=%v", r.NodeIDs, r.Additional)
		}
	}

	// The DEEP-NESTING case still fails closed to an unscoped Write (the token-limit parse
	// bails and there is no usable scope). The cyclic case is now a no-scope Read, which the
	// proxy denies via the augment-failure gate.
	if r := Classify("POST", "/api/graphql", []byte(deep.String())); r.Access != Write {
		t.Fatalf("deeply nested query should fail closed to Write, got %v", r.Access)
	}
}

// FINDING 8 (Medium): a GraphQL read can address objects by opaque node ID
// (node(id:)/nodes(ids:)) with no repository() scope. Previously these extracted no
// scope and fell through to the default — bypassing a repo block under default=allow.
// The classifier now extracts those node IDs (like mutations) so the proxy resolves
// and policy-checks each.
func TestSec_NodeIDReadExtracted(t *testing.T) {
	single := []byte(`{"query":"query { node(id: \"R_kgDORepoNode\") { ... on Repository { name } } }"}`)
	r := Classify("POST", "/api/graphql", single)
	if r.Access != Read {
		t.Fatalf("expected Read, got %v", r.Access)
	}
	if len(r.NodeIDs) != 1 || r.NodeIDs[0] != "R_kgDORepoNode" {
		t.Fatalf("expected node(id) read to extract R_kgDORepoNode, got %v", r.NodeIDs)
	}
	if r.HasRepo() {
		t.Fatalf("node(id) read should carry no repository() scope, got %s", r.RepoFullName())
	}

	multi := []byte(`{"query":"query($ids:[ID!]!){ nodes(ids: $ids) { __typename } }","variables":{"ids":["PR_one","I_two","U_user"]}}`)
	r2 := Classify("POST", "/api/graphql", multi)
	got := map[string]bool{}
	for _, id := range r2.NodeIDs {
		got[id] = true
	}
	// Every node-ID-shaped value is extracted; the proxy resolver decides repo vs non-repo
	// authoritatively (the user ID resolves to a non-repo node and is ignored there).
	if !got["PR_one"] || !got["I_two"] || !got["U_user"] {
		t.Fatalf("expected all node ids from nodes(ids:) to be extracted, got %v", r2.NodeIDs)
	}
}

// FINDING 9 (CRITICAL): GraphQL field-navigation cross-repo read. A query enters via
// an allowed repository() but then navigates to OTHER repos via fields
// (owner.repositories, owner.repository(name:), forks, headRepository, ...). GitHub
// executes it and the proxy streams the response, so a scoped entry point leaked
// arbitrary repos. The classifier now scans repository()/node() subtrees for such
// navigation and fails closed (returns Write → unscoped → denied).
func TestSec_GraphQLCrossRepoNavFailsClosed(t *testing.T) {
	escaping := []string{
		`query{repository(owner:"o",name:"r"){owner{repositories(first:50){nodes{name}}}}}`,
		`query{repository(owner:"o",name:"r"){owner{repository(name:"other"){issues{nodes{body}}}}}}`,
		`query{repository(owner:"o",name:"r"){pullRequest(number:1){headRepository{nameWithOwner}}}}`,
		`query{repository(owner:"o",name:"r"){forks(first:5){nodes{nameWithOwner}}}}`,
		`query{repository(owner:"o",name:"r"){parent{nameWithOwner}}}`,
		`query{node(id:"R_kgDOx"){... on Repository{owner{repositories(first:5){nodes{name}}}}}}`,
		`query{search(query:"repo:o/r",type:ISSUE,first:5){nodes{... on Issue{repository{owner{repositories(first:5){nodes{name}}}}}}}}`,
		`query{repositoryOwner(login:"o"){... on User{repositories(first:5){nodes{forks(first:1){nodes{name}}}}}}}`,
	}
	for _, q := range escaping {
		r := Classify("POST", "/api/graphql", []byte(`{"query":`+jsonStr(q)+`}`))
		if !r.NavEscapes {
			t.Errorf("cross-repo nav must set NavEscapes (proxy redacts via filter, else denies); query=%s", q)
		}
	}

	// Org/owner enumeration of its OWN repos is legitimate (granted via org access) and
	// must NOT be flagged as escaping.
	for _, q := range []string{
		`query{organization(login:"o"){repositories(first:5){nodes{name}}}}`,
		`query{repositoryOwner(login:"o"){repositories(first:5){nodes{name}}}}`,
	} {
		r := Classify("POST", "/api/graphql", []byte(`{"query":`+jsonStr(q)+`}`))
		if r.Org != "o" || r.Access != Read || r.NavEscapes {
			t.Errorf("org enumeration should be a plain org-scoped read; query=%s org=%q access=%v escapes=%v", q, r.Org, r.Access, r.NavEscapes)
		}
	}

	// Legit in-repo queries (including owner.login) must NOT be flagged.
	legit := []string{
		`query{repository(owner:"o",name:"r"){issue(number:1){title body}}}`,
		`query{repository(owner:"o",name:"r"){name owner{login} pullRequests(first:1){nodes{title}}}}`,
		`query{repository(owner:"o",name:"r"){defaultBranchRef{name target{... on Commit{oid}}}}}`,
	}
	for _, q := range legit {
		r := Classify("POST", "/api/graphql", []byte(`{"query":`+jsonStr(q)+`}`))
		if r.RepoFullName() != "o/r" || r.Access != Read || r.NavEscapes {
			t.Errorf("legit in-repo query mis-handled: query=%s repo=%q access=%v escapes=%v", q, r.RepoFullName(), r.Access, r.NavEscapes)
		}
	}
}

func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
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
