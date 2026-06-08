package classifier

import (
	"testing"

	"better-gh/internal/gqlfilter"
)

// TestR39_OwnerContentResourceInSync couples the RESPONSE-side owner-content map (gqlfilter.ownerContentResource,
// round-39: nulls a navigated org/enterprise content field when its resource is denied) to the REQUEST-side
// classifier maps, so the two sides cannot diverge. (1) Every gqlfilter content field must map to the SAME
// resource in gqlOrgFieldToResource or gqlEnterpriseFieldToResource. (2) Every classifier CONTENT field (not a
// member/team key, not a member-mechanism field) must be present response-side — otherwise a carve-out is
// enforced at the request gate but bypassed on a navigation path the request scope cannot reach.
func TestR39_OwnerContentResourceInSync(t *testing.T) {
	gqlMap := gqlfilter.OwnerContentResource()
	// (1) forward: gqlfilter ⊆ classifier, same resource. The viewer-private sentinel fields
	// (sponsorshipForViewerAs*) are gated on the user_private CATEGORY (not an org/enterprise per-resource
	// key), so they are classified via viewerPrivateFieldCategory at the roots, not gqlOrgFieldToResource —
	// exclude them from this request↔response per-resource coupling.
	viewerPrivateSentinel := map[string]bool{
		"sponsorshipForViewerAsSponsor": true, "sponsorshipForViewerAsSponsorable": true,
		"viewerIsSponsoring": true, "isSponsoringViewer": true, "viewerCanSponsor": true,
	}
	for field, res := range gqlMap {
		if viewerPrivateSentinel[field] {
			if viewerPrivateFieldCategory[field] != "user_private" {
				t.Errorf("viewer-private sentinel field %q must be classified user_private at the roots, got %q", field, viewerPrivateFieldCategory[field])
			}
			continue
		}
		if gqlOrgFieldToResource[field] != res && gqlEnterpriseFieldToResource[field] != res {
			t.Errorf("gqlfilter.ownerContentResource[%q]=%q but classifier maps it to org=%q/ent=%q — request/response mismatch",
				field, res, gqlOrgFieldToResource[field], gqlEnterpriseFieldToResource[field])
		}
	}
	// member-mechanism fields (handled by the ownerMember marker, not the content marker) are excluded.
	memberHandled := map[string]bool{
		"members": true, "administrators": true, "ownerInfo": true, "memberInvitations": true,
		"membersWithRole": true, "pendingMembers": true, "memberStatuses": true, "mannequins": true,
		"enterpriseOwners": true, "samlIdentityProvider": true, "auditLog": true,
		"enterpriseTeam": true, "enterpriseTeams": true, "team": true, "teams": true,
	}
	// (2) reverse: every classifier content field is enforced response-side.
	for _, m := range []map[string]string{gqlOrgFieldToResource, gqlEnterpriseFieldToResource} {
		for field, res := range m {
			if res == "members" || res == "teams" || memberHandled[field] {
				continue
			}
			if gqlMap[field] == "" {
				t.Errorf("classifier content field %q (resource %q) is missing from gqlfilter.ownerContentResource — "+
					"a carve-out is enforced at the request gate but bypassed on a navigation path", field, res)
			}
		}
	}
}

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
