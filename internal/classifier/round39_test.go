package classifier

import "testing"

// TestR39_OrgPackagesIssuesGated pins the round-39 finding-1/2/6 front-gate fix: org packages and
// issue-type/field config (whose element @docsCategory is packages/issues — outside the round-38
// {orgs,enterprise-admin} guard set) now gate on their REST per-resource key over GraphQL, so a
// [org.permissions] packages="none"/issue-types="none" carve-out the REST sibling enforces is honored.
func TestR39_OrgPackagesIssuesGated(t *testing.T) {
	for q, res := range map[string]string{
		`{ organization(login:"acme"){ packages(first:5){ nodes{ name } } } }`:                                         "packages",
		`{ organization(login:"acme"){ issueTypes(first:5){ nodes{ name } } } }`:                                       "issue-types",
		`{ organization(login:"acme"){ issueFields(first:5){ nodes{ name } } } }`:                                      "issue-fields",
		`{ repository(owner:"acme",name:"pub"){ owner{ ...on Organization{ packages(first:1){ nodes{ name } } } } } }`: "packages",
	} {
		r := Classify("POST", "/graphql", []byte(`{"query":`+jsonStr(q)+`}`))
		if !r37HasScope(r.AllScopes(), "", "", "acme", res) {
			t.Errorf("%s missing org %q resource scope (bypasses the carve-out): %+v", q, res, r.AllScopes())
		}
	}
}
