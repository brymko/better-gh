package gqlfilter

import (
	"strings"
	"testing"
)

// TestR28_UserSponsorsPrivateRedacted pins the round-28 fix: a DENIED User reached via an interface
// (Sponsorable/ProfileOwner) leaks its owner-private sponsors financials / verified-domain emails unless
// precisely nulled — but a User reached without selecting a private field (issue.author) must NOT be
// marked (it is reached everywhere; coarse-redacting it would null every user under default-deny).
func TestR28_UserSponsorsPrivateRedacted(t *testing.T) {
	s, _ := Load()
	out, err := s.Augment(`{ organization(login:"a"){ sponsorshipsAsSponsor(first:1){ nodes{ sponsorable{ monthlyEstimatedSponsorsIncomeInCents } } } } }`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "on User") || !strings.Contains(out, userMarkerAlias) {
		t.Fatalf("User private field via interface not marked:\n%s", out)
	}
	out2, err := s.Augment(`{ repository(owner:"a",name:"r"){ issue(number:1){ author{ login } } } }`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out2, userMarkerAlias) {
		t.Fatalf("issue.author{login} wrongly user-marked — would over-redact every author under default-deny:\n%s", out2)
	}

	denied := func(owner, _ string) bool { return owner == "alice" }
	// denied user's income nulled, login (public) kept
	red := RedactDeniedOwnerPrivate(map[string]any{"sponsorable": map[string]any{
		userMarkerAlias: "alice", ownerMemberMarkerPrefix + "inc": "User",
		"inc": "ALICE_INCOME", "login": "alice",
	}}, denied).(map[string]any)
	if s := mustJSON(red); strings.Contains(s, "ALICE_INCOME") {
		t.Fatalf("denied user's sponsors income leaked: %s", s)
	}
	if s := mustJSON(red); !strings.Contains(s, "alice") || strings.Contains(s, "bghOwner") {
		t.Fatalf("user login wrongly redacted or marker leaked: %s", s)
	}
	// an ALLOWED user's income is kept (operator granted it)
	keep := RedactDeniedOwnerPrivate(map[string]any{"sponsorable": map[string]any{
		userMarkerAlias: "bob", ownerMemberMarkerPrefix + "inc": "User", "inc": "BOB_INCOME", "login": "bob",
	}}, denied).(map[string]any)
	if s := mustJSON(keep); !strings.Contains(s, "BOB_INCOME") {
		t.Fatalf("allowed user's income wrongly redacted: %s", s)
	}
}

// TestR28_UserPrivateFieldsCoverSponsorsFinancials is the anti-drift guard for the curated userPrivateFields
// set: every Sponsorable financial field (name ends in "InCents") must be in it, so a schema refresh that
// adds another sponsors-income scalar fails the build instead of leaking it for a denied user.
func TestR28_UserPrivateFieldsCoverSponsorsFinancials(t *testing.T) {
	s, _ := Load()
	sp := s.schema.Types["Sponsorable"]
	if sp == nil {
		t.Skip("no Sponsorable interface")
	}
	for _, f := range sp.Fields {
		if strings.HasSuffix(f.Name, "InCents") && !userPrivateFields[f.Name] {
			t.Errorf("Sponsorable financial field %q is not in userPrivateFields — it leaks for a denied user "+
				"reached via an interface; add it", f.Name)
		}
	}
}
