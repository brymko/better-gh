package classifier

import "testing"

// Regression for FINDING E (CRITICAL): node IDs hidden inside a fragment spread or inline
// fragment were not extracted, because walkSelectionArgs traversed only plain fields.
// GitHub executes a mutation field reached through a fragment, so the denied-repo node
// rode along unresolved and unchecked. Both fragment forms must now be extracted.
func TestSec_NodeIDInFragmentsExtracted(t *testing.T) {
	cases := map[string]string{
		"fragment spread": `{"query":"mutation { enablePullRequestAutoMerge(input:{pullRequestId:\"PR_carrier\"}){clientMutationId} ...Evil } fragment Evil on Mutation { closePullRequest(input:{pullRequestId:\"PR_blocked\"}){clientMutationId} }"}`,
		"inline fragment": `{"query":"mutation { enablePullRequestAutoMerge(input:{pullRequestId:\"PR_carrier\"}){clientMutationId} ... on Mutation { closePullRequest(input:{pullRequestId:\"PR_blocked\"}){clientMutationId} } }"}`,
		"nested spread":   `{"query":"mutation { ...A } fragment A on Mutation { ...B } fragment B on Mutation { closePullRequest(input:{pullRequestId:\"PR_blocked\"}){clientMutationId} }"}`,
	}
	for name, body := range cases {
		r := Classify("POST", "/api/graphql", []byte(body))
		got := map[string]bool{}
		for _, id := range r.NodeIDs {
			got[id] = true
		}
		if !got["PR_blocked"] {
			t.Errorf("%s: node ID inside fragment not extracted; NodeIDs=%v", name, r.NodeIDs)
		}
	}
}

// Regression for FINDING F (CRITICAL): a variable's DEFAULT value is what GitHub uses when
// the request omits it, so a default-supplied repository owner/name or mutation node ID
// must be scoped/extracted. resolveStringArg/walkArgValue previously ignored defaults.
func TestSec_VariableDefaultsResolved(t *testing.T) {
	repoQ := []byte(`{"query":"query($o:String=\"victim\",$n:String=\"private\"){ repository(owner:$o,name:$n){ pullRequest(number:1){ title } } }"}`)
	r := Classify("POST", "/api/graphql", repoQ)
	if !scopesContainRepo(r, "victim", "private") {
		t.Errorf("variable-default repository not scoped; AllScopes=%+v", r.AllScopes())
	}

	mutQ := []byte(`{"query":"mutation($id:ID=\"PR_blocked\"){ closePullRequest(input:{pullRequestId:$id}){clientMutationId} }"}`)
	r2 := Classify("POST", "/api/graphql", mutQ)
	found := false
	for _, id := range r2.NodeIDs {
		if id == "PR_blocked" {
			found = true
		}
	}
	if !found {
		t.Errorf("variable-default mutation node ID not extracted; NodeIDs=%v", r2.NodeIDs)
	}

	// A provided value must still win over the default.
	mutProvided := []byte(`{"query":"mutation($id:ID=\"PR_default\"){ closePullRequest(input:{pullRequestId:$id}){clientMutationId} }","variables":{"id":"PR_provided"}}`)
	r3 := Classify("POST", "/api/graphql", mutProvided)
	got := map[string]bool{}
	for _, id := range r3.NodeIDs {
		got[id] = true
	}
	if !got["PR_provided"] {
		t.Errorf("provided variable value should be extracted; NodeIDs=%v", r3.NodeIDs)
	}
}

// Regression for FINDING G (MEDIUM): a multi-root mutation must tag each node ID with the
// resource of the root field that referenced it, not a single resource for the whole
// request. Otherwise a permitted-resource field (pulls) lets a restricted-resource field
// (issues) ride along in the same repo.
func TestSec_MultiRootMutationPerNodeResource(t *testing.T) {
	body := []byte(`{"query":"mutation { enablePullRequestAutoMerge(input:{pullRequestId:\"PR_x\"}){clientMutationId} createIssue(input:{repositoryId:\"R_y\",title:\"t\"}){clientMutationId} }"}`)
	r := Classify("POST", "/api/graphql", body)
	if r.NodeIDResource["PR_x"] != "pulls" {
		t.Errorf("PR_x should map to resource pulls, got %q", r.NodeIDResource["PR_x"])
	}
	if r.NodeIDResource["R_y"] != "issues" {
		t.Errorf("R_y (createIssue) should map to resource issues, got %q", r.NodeIDResource["R_y"])
	}
}
