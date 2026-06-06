package gqlfilter

import (
	"strings"
	"testing"
)

// TestR27_InterfaceOwnerMarked: an owner reached through an interface field via COMMON fields (no inline
// fragment) gets the owner marker, so a base-denied owner's owner-private common fields are coarse-redacted.
func TestR27_InterfaceOwnerMarked(t *testing.T) {
	s, _ := Load()
	out, err := s.Augment(`{ organization(login:"a"){ sponsorshipsAsSponsor(first:1){ nodes{ sponsorable{ monthlyEstimatedSponsorsIncomeInCents } } } } }`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "on Organization") || !strings.Contains(out, ownerMarkerAlias) {
		t.Fatalf("interface field to an owner not owner-marked:\n%s", out)
	}
	// base-denied owner reached via interface → income nulled (coarse), login kept.
	red := RedactDeniedOwnerPrivate(map[string]any{
		"sponsorable": map[string]any{ownerMarkerAlias: "secretco", "login": "secretco", "monthlyEstimatedSponsorsIncomeInCents": float64(777888)},
	}, func(owner, res string) bool { return owner == "secretco" }).(map[string]any)
	if s := mustJSON(red); strings.Contains(s, "777888") {
		t.Fatalf("denied owner's sponsors income leaked via interface nav: %s", s)
	}
}

// TestR27_EnterpriseTeamMembersRedacted: EnterpriseTeam.enterpriseTeamMembers is attributed to its ambient
// enterprise and nulled under the enterprise's members="none".
func TestR27_EnterpriseTeamMembersRedacted(t *testing.T) {
	denied := func(owner, res string) bool { return owner == "acme-ent" && res == "members" }
	red := RedactDeniedOwnerPrivate(map[string]any{
		ownerMarkerAlias: "acme-ent",
		"enterpriseTeams": map[string]any{"nodes": []any{map[string]any{
			ownerMemberMarkerPrefix + "enterpriseTeamMembers": "EnterpriseTeam",
			"enterpriseTeamMembers":                           map[string]any{"nodes": []any{map[string]any{"login": "ent-secret"}}},
		}}},
	}, denied).(map[string]any)
	if s := mustJSON(red); strings.Contains(s, "ent-secret") {
		t.Fatalf("EnterpriseTeam roster leaked under enterprise members=none: %s", s)
	}
}
