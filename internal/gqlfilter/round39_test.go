package gqlfilter

import (
	"strings"
	"testing"
)

// TestR39_NavigatedOrgContentRedacted pins the round-39 finding-4/8 fix: a navigated Organization/Enterprise's
// owner-private CONTENT field is nulled when its per-resource key is denied — even on a base-ALLOWED owner (the
// per-resource carve-out case the request-side scope missed on navigation paths). The content marker carries
// the resource alias-immune (via the resource code in its prefix), so a client alias on the field can't dodge it.
func TestR39_NavigatedOrgContentRedacted(t *testing.T) {
	// org "acme" base-ALLOWED but rulesets denied (the F4/F8 carve-out case).
	rulesetsDenied := func(owner, resource string) bool { return owner == "acme" && resource == "rulesets" }
	body := func() map[string]any {
		return map[string]any{
			ownerMarkerAlias: "acme",
			ownerContentMarkerPrefix + resourceCode("rulesets") + "__myRules":        "Organization", // ALIASED field `myRules: rulesets`
			ownerContentMarkerPrefix + resourceCode("settings") + "__billingContact": "Organization", // settings (allowed) → kept
			"myRules":        map[string]any{"nodes": []any{map[string]any{"name": "SECRET_RULESET"}}},
			"billingContact": "ops@acme.example",
			"name":           "AcmeInc", // public identity → kept
		}
	}
	red := RedactDeniedOwnerPrivate(body(), rulesetsDenied, noUserFieldDenied).(map[string]any)
	js := mustJSON(red)
	if strings.Contains(js, "SECRET_RULESET") {
		t.Fatalf("navigated org rulesets not nulled under rulesets-denied (alias myRules): %s", js)
	}
	if !strings.Contains(js, "ops@acme.example") {
		t.Fatalf("settings field wrongly nulled when only rulesets denied: %s", js)
	}
	if !strings.Contains(js, "AcmeInc") || strings.Contains(js, "bghOwner") {
		t.Fatalf("public identity nulled or marker leaked: %s", js)
	}

	// when rulesets is ALLOWED (no carve-out), the content is kept.
	allowed := func(owner, resource string) bool { return false }
	keep := RedactDeniedOwnerPrivate(body(), allowed, noUserFieldDenied).(map[string]any)
	if !strings.Contains(mustJSON(keep), "SECRET_RULESET") {
		t.Fatalf("rulesets wrongly nulled when the resource is allowed: %s", mustJSON(keep))
	}

	// a BASE-denied owner still coarse-redacts everything (content marker stripped, field nulled).
	baseDenied := func(owner, resource string) bool { return owner == "acme" }
	coarse := RedactDeniedOwnerPrivate(body(), baseDenied, noUserFieldDenied).(map[string]any)
	cj := mustJSON(coarse)
	if strings.Contains(cj, "SECRET_RULESET") || strings.Contains(cj, "ops@acme.example") {
		t.Fatalf("base-denied owner leaked content: %s", cj)
	}
}

// TestR39_EnterpriseOwnerInfoInventoryRedacted pins the round-39 finding-5 fix: the enterprise's member-org
// inventory reached one hop below enterprise(slug:) via ownerInfo.*SettingOrganizations is nulled under an
// organizations="none" carve-out, attributed to the ambient enterprise — closing the leak the coarse
// base-denied redaction could not (login/name IS the inventory secret there).
func TestR39_EnterpriseOwnerInfoInventoryRedacted(t *testing.T) {
	orgsDenied := func(owner, resource string) bool { return owner == "acme-ent" && resource == "organizations" }
	body := map[string]any{
		ownerMarkerAlias: "acme-ent", // the enterprise (base-allowed)
		"name":           "AcmeEnt",
		"ownerInfo": map[string]any{ // EnterpriseOwnerInfo — no owner marker, content-marked, attributed to ambient
			ownerContentMarkerPrefix + resourceCode("organizations") + "__inv": "EnterpriseOwnerInfo",
			"inv": map[string]any{"nodes": []any{map[string]any{"login": "SECRET_MEMBER_ORG"}}}, // aliased *SettingOrganizations
		},
	}
	red := RedactDeniedOwnerPrivate(body, orgsDenied, noUserFieldDenied).(map[string]any)
	if js := mustJSON(red); strings.Contains(js, "SECRET_MEMBER_ORG") {
		t.Fatalf("enterprise org inventory (ownerInfo.*SettingOrganizations) not nulled under organizations-denied: %s", js)
	}

	// augment must inject the content marker on a *SettingOrganizations field.
	s, _ := Load()
	out, err := s.Augment(`{ enterprise(slug:"e"){ ownerInfo{ defaultRepositoryPermissionSettingOrganizations(value:READ, first:5){ nodes{ login } } } } }`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, ownerContentMarkerPrefix+resourceCode("organizations")+"__defaultRepositoryPermissionSettingOrganizations") {
		t.Fatalf("EnterpriseOwnerInfo.*SettingOrganizations not content-marked:\n%s", out)
	}
}

// TestR39_AugmentMarksOrgContent verifies the augmenter injects a content marker (carrying the resource code)
// for an owner-private content field selected on a navigated Organization.
func TestR39_AugmentMarksOrgContent(t *testing.T) {
	s, _ := Load()
	out, err := s.Augment(`{ repository(owner:"a",name:"r"){ owner{ ... on Organization {
		rules: rulesets(first:5){ nodes{ name } } organizationBillingEmail } } } }`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, ownerContentMarkerPrefix+resourceCode("rulesets")+"__rules") {
		t.Fatalf("rulesets content marker (aliased `rules`) not injected:\n%s", out)
	}
	if !strings.Contains(out, ownerContentMarkerPrefix+resourceCode("settings")+"__organizationBillingEmail") {
		t.Fatalf("organizationBillingEmail content marker (settings) not injected:\n%s", out)
	}
}
