package classifier

import (
	"testing"

	"better-gh/internal/gqlfilter"
)

// TestR22_AuditLogScopedToMembers pins the round-22 fix: organization(login:){auditLog} (the member
// roster + IPs + activity) must scope to the "members" per-resource key so a [org.permissions]
// members="none" carve-out denies it, instead of degrading to base org read.
func TestR22_AuditLogScopedToMembers(t *testing.T) {
	body := `{"query":"{ organization(login:\"acme\"){ auditLog(first:100){ nodes{ ... on OrgAddMemberAuditEntry { actorLogin actorIp } } } } }"}`
	r := Classify("POST", "/graphql", []byte(body))
	if !hasScope(r.AllScopes(), "", "", "acme", "members") {
		t.Fatalf("organization{auditLog} must scope to org=acme resource=members, got %+v", r.AllScopes())
	}
}

// TestR22_OrgMemberIdentityCoverage is the coverage guard for the recurring org member-identity class
// (round-21 mannequins/memberStatuses/…, round-22 auditLog): EVERY Organization field the schema shows
// can surface a member/owner identity (login/email/IP) must be mapped to "members" in
// gqlOrgFieldToResource — or be a justified public-data exception. Every such field in the embedded schema must be covered rather than silently bypassing members="none" over GraphQL.
func TestR22_OrgMemberIdentityCoverage(t *testing.T) {
	s, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	// sponsoring/sponsors expose the logins/emails of accounts in a PUBLIC sponsorship relationship
	// (GitHub Sponsors is public), not the org's private member roster — so they are base-governed, not
	// member-identity. Kept explicit so a genuinely-new member field is not silently absorbed.
	publicSponsorship := map[string]bool{"sponsoring": true, "sponsors": true}

	for _, field := range s.OrgMemberIdentityFields() {
		if publicSponsorship[field] {
			continue
		}
		if gqlOrgFieldToResource[field] != "members" {
			t.Errorf("Organization.%s surfaces member/owner identity but is not mapped to \"members\" in "+
				"gqlOrgFieldToResource (got %q) — it bypasses a members=\"none\" carve-out over GraphQL; map "+
				"it, or add it to publicSponsorship if it is genuinely public", field, gqlOrgFieldToResource[field])
		}
	}
}
