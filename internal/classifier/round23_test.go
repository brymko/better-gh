package classifier

import (
	"fmt"
	"testing"
)

// TestR23_RepositoryOwnerMemberScoped pins the round-23 H-1 fix: member-identity reached via the
// repository().owner navigation path (not just the organization(login:) root) must scope to the org's
// "members" key, so a [org.permissions] members="none" carve-out denies it.
func TestR23_RepositoryOwnerMemberScoped(t *testing.T) {
	for _, field := range []string{
		"membersWithRole(first:100){ nodes{ login email } }",
		"mannequins(first:100){ nodes{ login email } }",
		"auditLog(first:100){ nodes{ ... on OrgAddMemberAuditEntry { actorLogin actorIp } } }",
	} {
		q := fmt.Sprintf(`{"query":"{ repository(owner:\"acme\", name:\"anyrepo\"){ owner { ... on Organization { %s } } } }"}`, field)
		r := Classify("POST", "/graphql", []byte(q))
		if !hasScope(r.AllScopes(), "", "", "acme", "members") {
			t.Errorf("repository().owner{%s} must scope to org=acme resource=members, got %+v", field, r.AllScopes())
		}
	}
	// a plain owner-metadata selection must NOT spuriously demand "members" (no over-scoping)
	r := Classify("POST", "/graphql", []byte(`{"query":"{ repository(owner:\"acme\", name:\"r\"){ owner { login } } }"}`))
	if hasScope(r.AllScopes(), "", "", "acme", "members") {
		t.Errorf("repository().owner{login} must not demand members, got %+v", r.AllScopes())
	}
}

// TestR23_BodyNamedReposScoped pins the round-23 H-2/M-1 fix and is the structural guard for the migration
// pathScopedSafeExceptions: a REST request that names a FOREIGN repo in its JSON body (migrations,
// variant-analyses) must scope that repo, so a denied target is rejected before the custodian acts on it.
func TestR23_BodyNamedReposScoped(t *testing.T) {
	body := []byte(`{"repositories":["acme/secret"],"repository_owners":["evil-org"]}`)
	for _, path := range []string{
		"/orgs/acme/migrations",
		"/user/migrations",
		"/repos/o/r/code-scanning/codeql/variant-analyses",
	} {
		r := Classify("POST", path, body)
		if !scopeNames(r.AllScopes(), "acme/secret") {
			t.Errorf("%s: body repository acme/secret must become a scope, got %+v", path, r.AllScopes())
		}
	}
	// repository_owners targets the whole owner — must become an org scope.
	r := Classify("POST", "/repos/o/r/code-scanning/codeql/variant-analyses", body)
	if !hasOrgScope(r.AllScopes(), "evil-org") {
		t.Errorf("variant-analyses repository_owners evil-org must become an org scope, got %+v", r.AllScopes())
	}
	// a GET (not a body-naming write) must not parse a body into scopes.
	if rg := Classify("GET", "/orgs/acme/migrations", body); scopeNames(rg.AllScopes(), "acme/secret") {
		t.Errorf("GET must not body-scope, got %+v", rg.AllScopes())
	}
}

func scopeNames(scopes []Scope, ownerRepo string) bool {
	for _, s := range scopes {
		if s.Owner+"/"+s.Repo == ownerRepo {
			return true
		}
	}
	return false
}

func hasOrgScope(scopes []Scope, org string) bool {
	for _, s := range scopes {
		if s.Org == org {
			return true
		}
	}
	return false
}
