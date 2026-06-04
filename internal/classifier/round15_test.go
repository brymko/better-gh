package classifier

import (
	"encoding/json"
	"testing"
)

func classifyGQL(t *testing.T, query string) Result {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"query": query})
	return Classify("POST", "/graphql", body)
}

// round-15 CRITICAL: a triple-quoted block string is a distinct ast.BlockValue, which the scope and
// node-ID collectors used to ignore — so a multi-root mutation could hide a denied WRITE target in a
// block string and ride a plain-string allowed sibling past policy. Both string forms must now be
// collected identically.
func TestR15_BlockStringRepoSpecCollected(t *testing.T) {
	r := classifyGQL(t, `mutation {
	  a: createCommitOnBranch(input:{branch:{repositoryNameWithOwner:"allowed/repo",branchName:"main"},message:{headline:"x"},expectedHeadOid:"d"}){commit{url}}
	  b: createCommitOnBranch(input:{branch:{repositoryNameWithOwner:"""denied/secret""",branchName:"main"},message:{headline:"y"},expectedHeadOid:"d"}){commit{url}}
	}`)
	got := map[string]bool{}
	for _, s := range r.AllScopes() {
		if s.Owner != "" {
			got[s.Owner+"/"+s.Repo] = true
		}
	}
	if !got["allowed/repo"] || !got["denied/secret"] {
		t.Fatalf("both plain + block-string repo targets must be scoped, got %v", got)
	}
}

func TestR15_BlockStringNodeIDCollected(t *testing.T) {
	r := classifyGQL(t, `mutation {
	  a: mergePullRequest(input:{pullRequestId:"PR_kwDOAllowed1"}){clientMutationId}
	  b: mergePullRequest(input:{pullRequestId:"""PR_kwDODenied2"""}){clientMutationId}
	}`)
	ids := map[string]bool{}
	for _, id := range r.NodeIDs {
		ids[id] = true
	}
	if !ids["PR_kwDOAllowed1"] || !ids["PR_kwDODenied2"] {
		t.Fatalf("both plain + block-string node IDs must be collected, got %v", r.NodeIDs)
	}
}

func TestR15_BlockStringRepositoryReadScoped(t *testing.T) {
	r := classifyGQL(t, `query { repository(owner:"""acme""", name:"""secret""") { name } }`)
	if r.Owner != "acme" || r.Repo != "secret" {
		t.Fatalf("block-string repository() must scope to acme/secret, got %q/%q", r.Owner, r.Repo)
	}
}

// round-15 HIGH: createCommitOnBranch writes/deletes repository FILE CONTENT despite its name
// containing "Branch", so it must be governed by `contents`, not `branches`.
func TestR15_CreateCommitOnBranchIsContents(t *testing.T) {
	if got := gqlMutationResource("createCommitOnBranch"); got != "contents" {
		t.Fatalf("createCommitOnBranch must map to contents, got %q", got)
	}
	// sibling ref mutations stay branches
	for _, n := range []string{"createRef", "deleteRef", "updateRef", "mergeBranch"} {
		if got := gqlMutationResource(n); got != "branches" {
			t.Fatalf("%s must map to branches, got %q", n, got)
		}
	}
}

// round-15 HIGH: the Git Data API maps to the per-resource key its operation actually touches, not a
// standalone "git" key that branches=none / contents=none / commits=none didn't cover.
func TestR15_GitDataResourceSplit(t *testing.T) {
	cases := map[string]string{
		"/repos/o/r/git/refs":            "branches",
		"/repos/o/r/git/refs/heads/main": "branches",
		"/repos/o/r/git/tags":            "branches",
		"/repos/o/r/git/blobs/abc":       "contents",
		"/repos/o/r/git/trees/abc":       "contents",
		"/repos/o/r/git/commits/abc":     "commits",
	}
	for p, want := range cases {
		if got := Classify("GET", p, nil).Resource; got != want {
			t.Errorf("%s: want resource %q, got %q", p, want, got)
		}
	}
	// a bare/unknown git sub-resource fails closed (ResourceUnknown) so writes can't inherit base.
	if got := Classify("POST", "/repos/o/r/git", nil).Resource; got != ResourceUnknown {
		t.Errorf("bare /git: want ResourceUnknown, got %q", got)
	}
}
