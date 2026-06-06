package restfilter

import "testing"

// TestR42_OrgRulesetsOpaque pins the round-42 F2 fix: the org rulesets read ops are recognized as
// opaque-repo-id endpoints (their conditions.repository_id.repository_ids[] and a required-workflow rule's
// parameters.workflows[].repository_id name repos by a name-less numeric id the body-scan cannot map), so
// the proxy fails them closed when not path-scoped. The repo-scoped /repos/{o}/{r}/rulesets sibling is gated
// by its path scope and is NOT in the opaque set.
func TestR42_OrgRulesetsOpaque(t *testing.T) {
	for _, p := range []string{"/orgs/acme/rulesets", "/orgs/acme/rulesets/5"} {
		if !HasOpaqueRepoID(p) {
			t.Errorf("%s should be opaque-repo-id (fail closed) but HasOpaqueRepoID==false", p)
		}
	}
	if HasOpaqueRepoID("/repos/acme/secret/rulesets") {
		t.Errorf("/repos/{o}/{r}/rulesets is path-scoped and must NOT be opaque-repo-id")
	}
}

// TestR42_UserBillingBareRepoScan pins the round-42 F6 fix at the body-scan layer: the enhanced-billing
// usage report names the custodian's own repos by a BARE repositoryName (no owner); qualified with the
// path-derived custodian login it is authorized, so a denied repo's usage metrics fail closed. (The proxy
// supplies the login via pathOwnerForScan for /users/{username}/… where the classifier sets no Owner/Org.)
func TestR42_UserBillingBareRepoScan(t *testing.T) {
	body := []byte(`{"usageItems":[{"product":"actions","repositoryName":"private-heavy","netAmount":12.5},
	                              {"product":"storage","repositoryName":"public-ok","netAmount":1.0}]}`)
	authorized := func(ownerRepo string) bool { return ownerRepo != "octocat/private-heavy" }
	denied, ok := ContainsDeniedRepo(body, "octocat", authorized)
	if !ok {
		t.Fatal("billing usage body should parse as JSON")
	}
	if !denied {
		t.Fatal("F6: denied repo named by bare repositoryName not caught when qualified with the path custodian login")
	}
	// with no qualifying org (the pre-fix scanOrg=="" behavior) the bare name cannot be authorized → missed.
	if d, _ := ContainsDeniedRepo(body, "", authorized); d {
		t.Fatal("sanity: a bare name cannot be authorized without a qualifying org")
	}
}
