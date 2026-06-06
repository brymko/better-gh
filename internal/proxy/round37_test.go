package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"better-gh/internal/policy"
)

// TestSec_R37_CreateCommitOnBranchStringFormBranchesNone: a token with contents=read-write but branches=none
// must NOT be able to advance a branch tip via the STRING-target form of createCommitOnBranch
// (branch:{repositoryNameWithOwner:…}). The Ref-node form was already gated on contents+branches (round-25);
// the string form bypassed branches=none until round-37. The mutation must be denied (403), never forwarded.
func TestSec_R37_CreateCommitOnBranchStringFormBranchesNone(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{{
			Name:        "o/r",
			Access:      policy.AccessRead,
			Permissions: map[string]policy.Access{"contents": policy.AccessReadWrite, "branches": policy.AccessNone},
		}},
	}
	var hit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"createCommitOnBranch":{"commit":{"url":"https://github.com/o/r/commit/x"}}}}`)
	}))
	t.Cleanup(upstream.Close)
	srv := httptest.NewServer(r15Handler(t, pol, upstream.URL))
	t.Cleanup(srv.Close)

	q := `mutation { createCommitOnBranch(input:{branch:{repositoryNameWithOwner:"o/r",branchName:"main"},` +
		`message:{headline:"x"},expectedHeadOid:"0000000000000000000000000000000000000000",` +
		`fileChanges:{additions:[{path:"ci.yml",contents:"aGFjaw=="}]}}){ commit{ url } } }`
	resp := postGQL(t, srv.URL, q)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("createCommitOnBranch string form must be denied under branches=none, got status %d: %s", resp.StatusCode, b)
	}
	if hit {
		t.Errorf("denied branch-write mutation reached upstream (it would have advanced the branch tip)")
	}
}
