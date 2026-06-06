package gqlfilter

import (
	"strings"
	"testing"

	"github.com/vektah/gqlparser/v2/ast"
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

// TestR40_AbstractCommonFieldContentMarked pins the round-39 mechanism gap: an owner-private CONTENT field
// selected as an interface COMMON field (Sponsorable.monthlyEstimatedSponsorsIncomeInCents,
// ProjectV2Owner.projectsV2, PackageOwner.packages …) resolves to an Organization/Enterprise with NO
// `... on Organization` inline fragment, so augment's CONCRETE content-marking branch never saw the field —
// only ownerMarkerFragment (the abstract round-27 owner marker) ran, and it injected ONLY member markers, not
// content markers. Result: the owner got an owner marker (so it was NOT base-coarse-redacted under base-allowed
// access) but its content field carried no content marker, so RedactDeniedOwnerPrivate left the per-resource
// carve-out unenforced and the org sponsors-financials / private projects / packages LEAKED. The classifier
// request gate does not scope this path either (it scopes only org/repositoryOwner/user/enterprise roots and
// repository().owner). Now ownerMarkerFragment also injects a content marker for every selected content field.
func TestR40_AbstractCommonFieldContentMarked(t *testing.T) {
	s, _ := Load()
	for _, c := range []struct{ q, marker string }{
		// Sponsorable common field → org sponsors financials.
		{`{ viewer { sponsorshipsAsSponsor(first:1){ nodes{ sponsorable { monthlyEstimatedSponsorsIncomeInCents } } } } }`,
			ownerContentMarkerPrefix + resourceCode("sponsors") + "__monthlyEstimatedSponsorsIncomeInCents"},
		// ProjectV2Owner common field (aliased) → org private projects.
		{`{ node(id:"x"){ ... on ProjectV2 { owner { mine: projectsV2(first:1){ nodes{ title } } } } } }`,
			ownerContentMarkerPrefix + resourceCode("projects") + "__mine"},
	} {
		out, err := s.Augment(c.q)
		if err != nil {
			t.Fatalf("augment %q: %v", c.q, err)
		}
		if !strings.Contains(out, c.marker) {
			t.Fatalf("abstract-common-field content marker %q NOT injected for %q:\n%s", c.marker, c.q, out)
		}
	}

	// E2E: org sponsors financials reached via Sponsorable common field, base-ALLOWED owner, sponsors DENIED.
	sponsorsDenied := func(owner, resource string) bool { return owner == "acme" && resource == "sponsors" }
	data := map[string]any{"viewer": map[string]any{"sponsorable": map[string]any{
		ownerMarkerAlias: "acme",
		ownerContentMarkerPrefix + resourceCode("sponsors") + "__monthlyEstimatedSponsorsIncomeInCents": "Organization",
		"monthlyEstimatedSponsorsIncomeInCents":                                                         4242424,
	}}}
	red := RedactDeniedOwnerPrivate(data, sponsorsDenied, noUserFieldDenied)
	if strings.Contains(mustJSON(red), "4242424") {
		t.Fatalf("org sponsors financials leaked under sponsors-denied via Sponsorable common-field nav: %s", mustJSON(red))
	}
}

// TestR40_AbstractContentMarkerCoverage is the build-time anti-drift guard for the round-39-mechanism gap:
// it DERIVES every (interface/union → owner-private CONTENT common field) pair from the live schema —
// exactly the paths where an Organization/Enterprise is reached without an inline fragment — and asserts
// ownerMarkerFragment injects a content marker for each. A schema refresh adding a new interface-common
// content field (or a new ownerContentResource entry) that ownerMarkerFragment forgets to mark fails the
// build, instead of silently reintroducing the navigation-path content leak.
func TestR40_AbstractContentMarkerCoverage(t *testing.T) {
	s, _ := Load()
	for name, def := range s.schema.Types {
		if def.Kind != ast.Interface && def.Kind != ast.Union {
			continue
		}
		hasOwner := false
		for _, pt := range s.schema.PossibleTypes[name] {
			if pt.Name == "Organization" || pt.Name == "Enterprise" {
				hasOwner = true
				break
			}
		}
		if !hasOwner {
			continue
		}
		for _, f := range def.Fields {
			res, ok := ownerContentResource[f.Name]
			if !ok {
				continue
			}
			sibling := ast.SelectionSet{&ast.Field{Name: f.Name}}
			frag := s.ownerMarkerFragment("Organization", sibling)
			want := ownerContentMarkerPrefix + resourceCode(res) + "__" + f.Name
			found := false
			for _, sel := range frag.SelectionSet {
				if af, ok := sel.(*ast.Field); ok && af.Alias == want {
					found = true
				}
			}
			if !found {
				t.Errorf("interface %s common content field %q (resource %q) is NOT content-marked by ownerMarkerFragment — "+
					"abstract-navigation content leak", name, f.Name, res)
			}
		}
	}
}
