package proxy

import (
	"net/http"
	"strings"
	"testing"
)

// Audit F1 (CRITICAL) regression: a mutation must not write into a denied repo by naming the
// target with a STRING (createCommitOnBranch's repositoryNameWithOwner) or a non-id-keyed node ID
// (addPullRequestReviewComment's inReplyTo) while a benign "carrier" node satisfies policy. The
// classifier now extracts both as scopes the policy ANDs, so the denied target is checked.

func TestSec_E2E_CrossRepoWrite_StringTargetPlusCarrier_Denied(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret)
	// createCommitOnBranch targets blocked-org/secret by STRING; carrier addStar resolves to an
	// allowed repo. Must be denied (the string target is a scope policy denies).
	q := `mutation{ createCommitOnBranch(input:{branch:{repositoryNameWithOwner:\"blocked-org/secret\",branchName:\"main\"},message:{headline:\"x\"},expectedHeadOid:\"0000000000000000000000000000000000000000\",fileChanges:{additions:[{path:\"ci.yml\",contents:\"aGFjaw==\"}]}}){ commit{ url } } carrier: addStar(input:{starrableId:\"R_kgDOAllowedRw\"}){ starrable{ __typename } } }`
	resp, err := client.Post(env.gheServer.URL+"/api/graphql", "application/json", strings.NewReader(`{"query":"`+q+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("string-named cross-repo write with carrier must be 403, got %d", resp.StatusCode)
	}
}

func TestSec_E2E_CrossRepoWrite_InReplyToPlusCarrier_Denied(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret)
	// inReplyTo (an ID NOT ending in id/ids) targets a comment in blocked-org/secret; carrier is allowed.
	q := `mutation{ addPullRequestReviewComment(input:{inReplyTo:\"PRRC_kwDOBlockedSecret1\",body:\"x\"}){ clientMutationId } carrier: addStar(input:{starrableId:\"R_kgDOAllowedRw\"}){ starrable{ __typename } } }`
	resp, err := client.Post(env.gheServer.URL+"/api/graphql", "application/json", strings.NewReader(`{"query":"`+q+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("inReplyTo cross-repo write with carrier must be 403, got %d", resp.StatusCode)
	}
}

// Positive control: a legitimate commit to an ALLOWED repo via repositoryNameWithOwner (no node
// IDs, no carrier) must still work — the string target becomes the primary scope, not an
// "unscoped write".
func TestSec_E2E_CrossRepoWrite_StringTargetAllowed_Forwarded(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret)
	q := `mutation{ createCommitOnBranch(input:{branch:{repositoryNameWithOwner:\"allowed-org/rw-repo\",branchName:\"main\"},message:{headline:\"x\"},expectedHeadOid:\"0000000000000000000000000000000000000000\",fileChanges:{additions:[{path:\"ci.yml\",contents:\"aGVsbG8=\"}]}}){ commit{ url } } }`
	resp, err := client.Post(env.gheServer.URL+"/api/graphql", "application/json", strings.NewReader(`{"query":"`+q+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("legit commit to an allowed repo via repositoryNameWithOwner must be allowed, got 403")
	}
}
