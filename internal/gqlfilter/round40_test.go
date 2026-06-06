package gqlfilter

import (
	"strings"
	"testing"

	"github.com/vektah/gqlparser/v2/ast"
)

// TestR40_ContentBearingNonOwnerCovered is the derived completeness guard for the round-40 class (round-39's
// hand-listed EnterpriseOwnerInfo missed Team / EnterpriseUserAccount): for every connection/object field on a
// known owner or content-carrier, if its element type CARRIES owner-private content (a field in
// ownerContentResource) and is not itself an owner / repo-scoped / member-mechanism / content-mechanism type,
// the build fails — so a schema refresh adding another such carrier is forced into a marking branch.
func TestR40_ContentBearingNonOwnerCovered(t *testing.T) {
	s, _ := Load()
	unwrap := func(tp *ast.Type) string {
		for tp.Elem != nil {
			tp = tp.Elem
		}
		return tp.Name()
	}
	elementType := func(f *ast.FieldDefinition) string {
		rt := unwrap(f.Type)
		if d := s.schema.Types[rt]; d != nil {
			for _, sub := range d.Fields {
				if sub.Name == "nodes" {
					return unwrap(sub.Type)
				}
			}
		}
		return rt
	}
	carriesOwnerContent := func(typeName string) bool {
		d := s.schema.Types[typeName]
		if d == nil {
			return false
		}
		for _, f := range d.Fields {
			if ownerContentResource[f.Name] != "" || contentBearingNonOwnerResource(typeName, f.Name) != "" {
				return true
			}
		}
		return false
	}
	handled := func(typeName string) bool {
		return typeName == "Organization" || typeName == "Enterprise" || typeName == "User" ||
			memberBearingNonOwnerTypes[typeName] != nil || contentBearingNonOwnerTypes[typeName] ||
			s.isRepoScoped(typeName) // repo content is gated by the repo markers, not the owner mechanism
	}
	for _, carrier := range []string{"Organization", "Enterprise", "Team", "EnterpriseOwnerInfo", "EnterpriseUserAccount"} {
		d := s.schema.Types[carrier]
		if d == nil {
			continue
		}
		for _, f := range d.Fields {
			// Skip a field the carrier ALREADY gates (content-marked / member-marked): the whole field is
			// nulled when denied, so its element never reaches the client and need not be handled itself.
			if ownerContentResource[f.Name] != "" || contentBearingNonOwnerResource(carrier, f.Name) != "" ||
				orgMemberFieldNames[f.Name] || enterpriseMemberFieldNames[f.Name] {
				continue
			}
			elem := elementType(f)
			if elem != carrier && carriesOwnerContent(elem) && !handled(elem) {
				t.Errorf("%s.%s returns %q which carries owner-private content but is not content-marked "+
					"(owner / memberBearingNonOwnerTypes / contentBearingNonOwnerTypes / repo-scoped) — it is "+
					"nav-bypassable; add it to a marking branch", carrier, f.Name, elem)
			}
		}
	}
}

// TestR40_NonOwnerContentMarked pins the round-40 finding-1/2/5 fix: owner-private CONTENT reached one hop
// below an owner via a NON-owner carrier (Team's project boards, EnterpriseUserAccount's org-membership
// inventory, EnterpriseOwnerInfo's settings-class fields) is content-marked, so a per-resource carve-out is
// enforced response-side on the navigation path the request gate cannot scope.
func TestR40_NonOwnerContentMarked(t *testing.T) {
	s, _ := Load()
	for _, c := range []struct{ q, marker string }{
		{`{ organization(login:"a"){ teams(first:1){ nodes{ pv: projectsV2(first:1){ nodes{ title } } } } } }`,
			ownerContentMarkerPrefix + resourceCode("projects") + "__pv"},
		{`{ enterprise(slug:"e"){ members(first:1){ nodes{ ...on EnterpriseUserAccount{ organizations(first:1){ nodes{ login } } } } } } }`,
			ownerContentMarkerPrefix + resourceCode("organizations") + "__organizations"},
		{`{ enterprise(slug:"e"){ ownerInfo{ domains(first:1){ nodes{ domain } } } } }`,
			ownerContentMarkerPrefix + resourceCode("settings") + "__domains"},
		{`{ enterprise(slug:"e"){ ownerInfo{ ipAllowListEntries(first:1){ nodes{ allowListValue } } } } }`,
			ownerContentMarkerPrefix + resourceCode("settings") + "__ipAllowListEntries"},
	} {
		out, err := s.Augment(c.q)
		if err != nil {
			t.Fatalf("augment %q: %v", c.q, err)
		}
		if !strings.Contains(out, c.marker) {
			t.Errorf("content marker %q not injected for %q:\n%s", c.marker, c.q, out)
		}
	}
}

// TestR40_NonOwnerContentRedacted pins that the content markers on the non-owner carriers are nulled under the
// ambient owner's carve-out.
func TestR40_NonOwnerContentRedacted(t *testing.T) {
	// (1) Team.projectsV2 under org acme, projects denied.
	projectsDenied := func(owner, resource string) bool { return owner == "acme" && resource == "projects" }
	teamBody := map[string]any{
		ownerMarkerAlias: "acme",
		"teams": map[string]any{"nodes": []any{map[string]any{
			ownerContentMarkerPrefix + resourceCode("projects") + "__pv": "Team",
			"pv":   map[string]any{"nodes": []any{map[string]any{"title": "SECRET_BOARD"}}},
			"name": "eng",
		}}},
	}
	if js := mustJSON(RedactDeniedOwnerPrivate(teamBody, projectsDenied, noUserFieldDenied)); strings.Contains(js, "SECRET_BOARD") {
		t.Fatalf("Team.projectsV2 not nulled under projects-denied (ambient org): %s", js)
	}

	// (2) EnterpriseUserAccount.organizations under enterprise acme-ent, organizations denied.
	orgsDenied := func(owner, resource string) bool { return owner == "acme-ent" && resource == "organizations" }
	entBody := map[string]any{
		ownerMarkerAlias:                    "acme-ent",
		ownerMemberMarkerPrefix + "members": "Enterprise",
		"members": map[string]any{"nodes": []any{map[string]any{
			ownerContentMarkerPrefix + resourceCode("organizations") + "__organizations": "EnterpriseUserAccount",
			"organizations": map[string]any{"nodes": []any{map[string]any{"login": "SECRET_MEMBER_ORG"}}},
			"login":         "alice",
		}}},
	}
	if js := mustJSON(RedactDeniedOwnerPrivate(entBody, orgsDenied, noUserFieldDenied)); strings.Contains(js, "SECRET_MEMBER_ORG") {
		t.Fatalf("EnterpriseUserAccount.organizations not nulled under organizations-denied: %s", js)
	}

	// (3) EnterpriseOwnerInfo.domains under settings denied.
	settingsDenied := func(owner, resource string) bool { return owner == "acme-ent" && resource == "settings" }
	eoiBody := map[string]any{
		ownerMarkerAlias: "acme-ent",
		"ownerInfo": map[string]any{
			ownerContentMarkerPrefix + resourceCode("settings") + "__domains": "EnterpriseOwnerInfo",
			"domains": map[string]any{"nodes": []any{map[string]any{"domain": "SECRET_VERIFIED_DOMAIN"}}},
		},
	}
	if js := mustJSON(RedactDeniedOwnerPrivate(eoiBody, settingsDenied, noUserFieldDenied)); strings.Contains(js, "SECRET_VERIFIED_DOMAIN") {
		t.Fatalf("EnterpriseOwnerInfo.domains not nulled under settings-denied: %s", js)
	}
}
