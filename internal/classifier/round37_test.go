package classifier

import (
	"testing"

	"better-gh/internal/gqlfilter"
	"github.com/vektah/gqlparser/v2/ast"
)

func r37HasScope(scopes []Scope, owner, repo, org, resource string) bool {
	for _, s := range scopes {
		if s.Owner == owner && s.Repo == repo && s.Org == org && s.Resource == resource {
			return true
		}
	}
	return false
}

// TestR37_CreateCommitOnBranchStringTargetGatesBranches pins the round-37 finding-3 fix: the string-target
// form of createCommitOnBranch (branch:{repositoryNameWithOwner:"o/r",branchName:"main"}) must emit BOTH the
// "contents" (mutation) resource AND the "branches" (Ref type) resource, so a branches="none" carve-out is
// enforced — the parity of the Ref-node form's nodeResourceKeys union. Before the fix only "contents" was
// emitted, so the string form advanced a branch tip despite branches="none".
func TestR37_CreateCommitOnBranchStringTargetGatesBranches(t *testing.T) {
	q := `mutation { createCommitOnBranch(input:{branch:{repositoryNameWithOwner:"o/r",branchName:"main"},` +
		`message:{headline:"x"},expectedHeadOid:"0000000000000000000000000000000000000000",` +
		`fileChanges:{additions:[{path:"ci.yml",contents:"aGFjaw=="}]}}){ commit{ url } } }`
	r := Classify("POST", "/graphql", []byte(`{"query":`+jsonStr(q)+`}`))
	scopes := r.AllScopes()
	if !r37HasScope(scopes, "o", "r", "", "branches") {
		t.Errorf("createCommitOnBranch string target missing the branches scope (bypasses branches=none): %+v", scopes)
	}
	if !r37HasScope(scopes, "o", "r", "", "contents") {
		t.Errorf("createCommitOnBranch string target missing the contents scope: %+v", scopes)
	}
}

// TestR37_OrgOwnerPrivateContentGated pins the round-37 finding-2 fix: an Organization's owner-private
// CONTENT (projectsV2/projects boards, sponsors financials/activity) reached via organization(login:) or
// repository().owner must be gated on its REST per-resource key (projects/sponsors), so a
// [org.permissions] projects="none"/sponsors="none" carve-out the REST sibling enforces is enforced over
// GraphQL too. Before the fix these degraded to base org read (Resource "") and bypassed the carve-out.
func TestR37_OrgOwnerPrivateContentGated(t *testing.T) {
	for q, res := range map[string]string{
		`{ organization(login:"acme"){ projectsV2(first:1){ nodes{ title } } } }`:                                "projects",
		`{ organization(login:"acme"){ projects(first:1){ nodes{ name } } } }`:                                   "projects",
		`{ organization(login:"acme"){ sponsorsActivities(first:1){ nodes{ action } } } }`:                       "sponsors",
		`{ organization(login:"acme"){ monthlyEstimatedSponsorsIncomeInCents } }`:                                "sponsors",
		`{ repository(owner:"acme",name:"pub"){ owner{ ...on Organization{ projectsV2{ nodes{ title } } } } } }`: "projects",
	} {
		r := Classify("POST", "/graphql", []byte(`{"query":`+jsonStr(q)+`}`))
		if !r37HasScope(r.AllScopes(), "", "", "acme", res) {
			t.Errorf("%s missing org %q resource scope (bypasses the carve-out): %+v", q, res, r.AllScopes())
		}
	}
}

// TestR37_OrgProjectsCategoryCovered is the derived guard: every Organization field whose return element is a
// ProjectV2/classic-Project board (@docsCategory projects/projects-classic) must be gated on the "projects"
// resource in gqlOrgFieldToResource, so a schema refresh adding a new org project field fails the build
// instead of silently bypassing a projects="none" carve-out over GraphQL (round-37).
func TestR37_OrgProjectsCategoryCovered(t *testing.T) {
	s, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	org := gqlfilter.SchemaType(s, "Organization")
	if org == nil {
		t.Skip("no Organization type")
	}
	unwrap := func(tp *ast.Type) string {
		for tp.Elem != nil {
			tp = tp.Elem
		}
		return tp.Name()
	}
	docsCategoryOf := func(typeName string) string {
		d := gqlfilter.SchemaType(s, typeName)
		if d == nil {
			return ""
		}
		if dir := d.Directives.ForName("docsCategory"); dir != nil {
			if a := dir.Arguments.ForName("name"); a != nil && a.Value != nil {
				return a.Value.Raw
			}
		}
		return ""
	}
	for _, f := range org.Fields {
		rt := unwrap(f.Type)
		elem := rt
		if d := gqlfilter.SchemaType(s, rt); d != nil {
			for _, sub := range d.Fields {
				if sub.Name == "nodes" {
					elem = unwrap(sub.Type)
				}
			}
		}
		if cat := docsCategoryOf(elem); cat == "projects" || cat == "projects-classic" {
			if gqlOrgFieldToResource[f.Name] != "projects" {
				t.Errorf("Organization field %q returns a %q board (@docsCategory %q) but is not gated on the "+
					"projects resource in gqlOrgFieldToResource — a [org.permissions] projects=none carve-out is "+
					"bypassed over GraphQL; map it to \"projects\"", f.Name, elem, cat)
			}
		}
	}
}
