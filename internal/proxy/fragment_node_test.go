package proxy

import (
	"net/http"
	"strings"
	"testing"

	"better-gh/internal/policy"
)

// Regression for FINDING E (CRITICAL) e2e: a mutation that carries an allowed node ID at
// the top level (authorizing the request) and smuggles a DENIED node ID inside a fragment
// spread / inline fragment must be denied — the smuggled field would otherwise execute
// against blocked-org/secret. The harness token policy denies blocked-org/secret.
func TestSec_E2E_FragmentSmuggledMutationDenied(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret)
	bodies := map[string]string{
		"fragment spread": `{"query":"mutation { enablePullRequestAutoMerge(input:{pullRequestId:\"PR_AllowedRwNode\"}){clientMutationId} ...Evil } fragment Evil on Mutation { closePullRequest(input:{pullRequestId:\"PR_BlockedSecretNode\"}){clientMutationId} }"}`,
		"inline fragment": `{"query":"mutation { enablePullRequestAutoMerge(input:{pullRequestId:\"PR_AllowedRwNode\"}){clientMutationId} ... on Mutation { closePullRequest(input:{pullRequestId:\"PR_BlockedSecretNode\"}){clientMutationId} } }"}`,
	}
	for name, body := range bodies {
		resp, err := client.Post(env.gheServer.URL+"/api/graphql", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: mutation writing to blocked-org/secret must be denied, got %d", name, resp.StatusCode)
		}
	}
}

// Regression for FINDING F (CRITICAL) e2e: a denied node ID supplied via a variable DEFAULT
// (no variables provided), alongside an allowed carrier node, must be denied.
func TestSec_E2E_VariableDefaultSmuggledMutationDenied(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret)
	body := `{"query":"mutation($id:ID=\"PR_BlockedSecretNode\"){ enablePullRequestAutoMerge(input:{pullRequestId:\"PR_AllowedRwNode\"}){clientMutationId} closePullRequest(input:{pullRequestId:$id}){clientMutationId} }"}`
	resp, err := client.Post(env.gheServer.URL+"/api/graphql", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("mutation writing to blocked-org/secret via variable default must be denied, got %d", resp.StatusCode)
	}
}

// Regression for FINDING G (MEDIUM) e2e: with rw-repo granted pulls=read-write over a read
// base, a multi-root mutation that leads with a pulls field and appends createIssue in the
// SAME repo must be denied — the issue write is checked against "issues" (→ base read), not
// the leading field's "pulls".
func TestSec_E2E_MultiRootMutationPerResourceEnforced(t *testing.T) {
	env := setup(t)
	pol := policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{{
			Name:        "allowed-org/rw-repo",
			Access:      policy.AccessRead,
			Permissions: map[string]policy.Access{"pulls": policy.AccessReadWrite},
		}},
	}
	_, secret, err := env.store.Create("pulls-only-token", pol)
	if err != nil {
		t.Fatal(err)
	}
	client := gheClient(secret)

	// Control: pulls-only write succeeds.
	pullsOnly := `{"query":"mutation { enablePullRequestAutoMerge(input:{pullRequestId:\"PR_AllowedRwNode\"}){clientMutationId} }"}`
	resp, err := client.Post(env.gheServer.URL+"/api/graphql", "application/json", strings.NewReader(pullsOnly))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("pulls write under pulls=read-write should be allowed, got 403")
	}

	// Exploit attempt: smuggle an issues write under the leading pulls field.
	smuggle := `{"query":"mutation { enablePullRequestAutoMerge(input:{pullRequestId:\"PR_AllowedRwNode\"}){clientMutationId} createIssue(input:{repositoryId:\"R_AllowedRwRepo\",title:\"x\"}){clientMutationId} }"}`
	resp2, err := client.Post(env.gheServer.URL+"/api/graphql", "application/json", strings.NewReader(smuggle))
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("createIssue smuggled under pulls must be denied (issues→base read), got %d", resp2.StatusCode)
	}
}
