package classifier

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Round-21 HIGH: member-identity Organization fields (mannequins/memberStatuses/enterpriseOwners/
// samlIdentityProvider) must scope to the "members" per-resource key so a [org.permissions]
// members="none" carve-out is enforced over GraphQL (they were omitted from the round-20 map).
func TestR21_OrgMemberIdentityFieldsScoped(t *testing.T) {
	for _, field := range []string{"mannequins", "memberStatuses", "enterpriseOwners"} {
		body := fmt.Sprintf(`{"query":"{ organization(login:\"acme\"){ %s(first:10){ nodes{ login } } } }"}`, field)
		r := Classify("POST", "/graphql", []byte(body))
		if !hasScope(r.AllScopes(), "", "", "acme", "members") {
			t.Errorf("organization{%s} must scope to org=acme resource=members, got %+v", field, r.AllScopes())
		}
	}
}

// Round-21 MEDIUM: the GraphQL enterprise(slug:) root must emit an org scope (the slug) so an [[org]]
// rule gates it, instead of emitting no scope and falling to Defaults.Mode. Round-38: billingEmail now
// maps to the "billing" per-resource key (the enterprise content-gating fix), so the scope is
// {Org:acme-ent, Resource:"billing"} — still scoped to the enterprise org, now carve-out-able.
func TestR21_EnterpriseRootScoped(t *testing.T) {
	r := Classify("POST", "/graphql", []byte(`{"query":"{ enterprise(slug:\"acme-ent\"){ billingEmail } }"}`))
	if !hasScope(r.AllScopes(), "", "", "acme-ent", "billing") {
		t.Fatalf("enterprise(slug){billingEmail} must scope to org=acme-ent resource=billing, got %+v", r.AllScopes())
	}
	// a pure-metadata selection still yields a base ("") scope.
	r2 := Classify("POST", "/graphql", []byte(`{"query":"{ enterprise(slug:\"acme-ent\"){ name } }"}`))
	if !hasScope(r2.AllScopes(), "", "", "acme-ent", "") {
		t.Fatalf("enterprise(slug){name} must scope to org=acme-ent base, got %+v", r2.AllScopes())
	}
}

// Round-22: the enterprise INVITATION roots carry the slug under `enterpriseSlug`, not `slug`, so the
// round-21 enterprise case (which resolved only `slug`) left enterpriseAdministratorInvitation unscoped
// and never handled enterpriseMemberInvitation → owner-private enterprise data leaked under
// Defaults.Mode=allow. Both must now scope to the enterprise org. (The *ByToken variants are secret-
// token-gated and intentionally left to the public allowlist — see gqlfilter TestQueryRootCoverage.)
func TestR22_EnterpriseInvitationRootsScoped(t *testing.T) {
	for _, root := range []string{
		`enterpriseAdministratorInvitation(enterpriseSlug:\"acme-ent\",userLogin:\"u\",role:OWNER)`,
		`enterpriseMemberInvitation(enterpriseSlug:\"acme-ent\",userName:\"u\")`,
	} {
		body := fmt.Sprintf(`{"query":"{ %s{ id } }"}`, root)
		r := Classify("POST", "/graphql", []byte(body))
		if !hasScope(r.AllScopes(), "", "", "acme-ent", "") {
			t.Errorf("%s must scope to org=acme-ent, got %+v", root, r.AllScopes())
		}
	}
}

// Round-21 LOW: a pathological multi-root × shared-fragment document must be bounded by the
// document-global visit budget and fail closed (unscoped → Write/denied), not walked quadratically.
func TestR21_MultiRootSharedFragmentBudget(t *testing.T) {
	var frag strings.Builder
	frag.WriteString("fragment F on Repository {")
	for i := 0; i < 600; i++ {
		fmt.Fprintf(&frag, " f%d", i)
	}
	frag.WriteString(" }")
	var q strings.Builder
	q.WriteString("query {")
	for i := 0; i < 600; i++ {
		fmt.Fprintf(&q, " r%d: repository(owner:\"o\",name:\"n\"){ ...F }", i)
	}
	q.WriteString(" } ")
	q.WriteString(frag.String())

	body, _ := json.Marshal(map[string]string{"query": q.String()})
	r := Classify("POST", "/graphql", body)
	// Budget-exhausted walk fails closed: classifyGraphQL returns an unscoped write (denied downstream).
	if r.Access != Write {
		t.Fatalf("multi-root×shared-fragment query must fail closed (Write), got Access=%v with %d scopes", r.Access, len(r.AllScopes()))
	}
}
