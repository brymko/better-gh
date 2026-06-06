package classifier

import (
	"testing"

	"better-gh/internal/gqlfilter"
	"github.com/vektah/gqlparser/v2/ast"
)

// TestR38_EnterpriseOwnerContentGated pins the round-38 finding-1 fix: the enterprise(slug:) root gates its
// owner-private CONTENT on a per-resource key (billingInfo→"billing", organizations→"organizations",
// rulesets→"rulesets", …), so a [org.permissions] carve-out the REST /enterprises/{slug}/<seg> sibling
// enforces is honored over GraphQL too. Before the fix every enterprise field degraded to base read.
func TestR38_EnterpriseOwnerContentGated(t *testing.T) {
	for q, res := range map[string]string{
		`{ enterprise(slug:"acme-ent"){ billingInfo{ totalAvailableLicenses } } }`:     "billing",
		`{ enterprise(slug:"acme-ent"){ billingEmail } }`:                              "billing",
		`{ enterprise(slug:"acme-ent"){ securityContactEmail } }`:                      "settings",
		`{ enterprise(slug:"acme-ent"){ organizations(first:50){ nodes{ login } } } }`: "organizations",
		`{ enterprise(slug:"acme-ent"){ rulesets(first:5){ nodes{ name } } } }`:        "rulesets",
	} {
		r := Classify("POST", "/graphql", []byte(`{"query":`+jsonStr(q)+`}`))
		if !r37HasScope(r.AllScopes(), "", "", "acme-ent", res) {
			t.Errorf("%s missing enterprise %q resource scope (bypasses the carve-out): %+v", q, res, r.AllScopes())
		}
	}
}

// TestR38_OrgRemainingContentGated pins the round-38 finding-5 fix: the org-admin content fields the round-37
// fix did NOT cover (rulesets/properties/ip-allow-list/domains/billing-email/announcement/interaction) now
// gate on their REST per-resource key over GraphQL (organization(login:) AND repository().owner).
func TestR38_OrgRemainingContentGated(t *testing.T) {
	for q, res := range map[string]string{
		`{ organization(login:"acme"){ rulesets(first:5){ nodes{ name } } } }`:                                         "rulesets",
		`{ organization(login:"acme"){ repositoryCustomProperties(first:5){ nodes{ propertyName } } } }`:               "properties",
		`{ organization(login:"acme"){ ipAllowListEntries(first:5){ nodes{ allowListValue } } } }`:                     "settings",
		`{ organization(login:"acme"){ domains(first:5){ nodes{ domain } } } }`:                                        "settings",
		`{ organization(login:"acme"){ organizationBillingEmail } }`:                                                   "settings",
		`{ organization(login:"acme"){ interactionAbility{ limit } } }`:                                                "interaction-limits",
		`{ repository(owner:"acme",name:"pub"){ owner{ ...on Organization{ rulesets(first:1){ nodes{ name } } } } } }`: "rulesets",
	} {
		r := Classify("POST", "/graphql", []byte(`{"query":`+jsonStr(q)+`}`))
		if !r37HasScope(r.AllScopes(), "", "", "acme", res) {
			t.Errorf("%s missing org %q resource scope (bypasses the carve-out): %+v", q, res, r.AllScopes())
		}
	}
}

// r38AdminExceptions are {orgs,enterprise-admin}-category Org/Enterprise fields intentionally NOT mapped to a
// per-resource key (justified-public or handled elsewhere). Kept EXPLICIT so the coverage guard flags a NEW
// such field instead of silently base-governing it.
var r38OrgAdminExceptions = map[string]bool{}
var r38EntAdminExceptions = map[string]bool{}

// TestR38_OwnerAdminContentCovered is the derived completeness guard for the owner-private-content class
// (round-37 org projects/sponsors → round-38 the rest + enterprise): every Organization/Enterprise field
// whose element @docsCategory is unambiguously owner-ADMIN-private ("orgs" / "enterprise-admin") must be gated
// on a per-resource key (so a [org.permissions] carve-out is honored over GraphQL) or be a justified
// exception. A schema refresh adding a new admin field to either type fails the build instead of silently
// degrading it to base org/enterprise read.
func TestR38_OwnerAdminContentCovered(t *testing.T) {
	s, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
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
	elemOf := func(f *ast.FieldDefinition) string {
		rt := unwrap(f.Type)
		if d := gqlfilter.SchemaType(s, rt); d != nil {
			for _, sub := range d.Fields {
				if sub.Name == "nodes" {
					return unwrap(sub.Type)
				}
			}
		}
		return rt
	}
	adminCats := map[string]bool{"orgs": true, "enterprise-admin": true}
	check := func(typeName string, fieldMap map[string]string, exceptions map[string]bool) {
		def := gqlfilter.SchemaType(s, typeName)
		if def == nil {
			t.Skipf("no %s type", typeName)
			return
		}
		for _, f := range def.Fields {
			if adminCats[docsCategoryOf(elemOf(f))] && fieldMap[f.Name] == "" && !exceptions[f.Name] {
				t.Errorf("%s.%s (@docsCategory %q) is owner-admin-private but not gated on a per-resource key — "+
					"a [org.permissions] carve-out is bypassed over GraphQL; map it (or justify it as an exception)",
					typeName, f.Name, docsCategoryOf(elemOf(f)))
			}
		}
	}
	check("Organization", gqlOrgFieldToResource, r38OrgAdminExceptions)
	check("Enterprise", gqlEnterpriseFieldToResource, r38EntAdminExceptions)

	// The admin SCALAR/repos-category fields (@docsCategory "" or "repos", which the category guard cannot
	// flag) must also stay mapped — pinned by name so a refactor cannot silently drop them.
	for _, f := range []string{"organizationBillingEmail", "rulesets", "ruleset", "repositoryCustomProperties", "interactionAbility"} {
		if gqlOrgFieldToResource[f] == "" {
			t.Errorf("Organization.%s must stay gated on a per-resource key", f)
		}
	}
	for _, f := range []string{"billingEmail", "securityContactEmail", "rulesets", "repositoryCustomProperties"} {
		if gqlEnterpriseFieldToResource[f] == "" {
			t.Errorf("Enterprise.%s must stay gated on a per-resource key", f)
		}
	}
	// And the PUBLIC identity fields must NOT be gated (so base org/enterprise read still returns them).
	for _, f := range []string{"name", "login", "description", "avatarUrl", "url", "location", "websiteUrl"} {
		if gqlOrgFieldToResource[f] != "" {
			t.Errorf("public Organization field %q must stay base-governed (not per-resource gated)", f)
		}
	}
}
