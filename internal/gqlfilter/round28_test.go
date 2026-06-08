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
	}}, denied, noUserFieldDenied).(map[string]any)
	if s := mustJSON(red); strings.Contains(s, "ALICE_INCOME") {
		t.Fatalf("denied user's sponsors income leaked: %s", s)
	}
	if s := mustJSON(red); !strings.Contains(s, "alice") || strings.Contains(s, "bghOwner") {
		t.Fatalf("user login wrongly redacted or marker leaked: %s", s)
	}
	// an ALLOWED user's income is kept (operator granted it)
	keep := RedactDeniedOwnerPrivate(map[string]any{"sponsorable": map[string]any{
		userMarkerAlias: "bob", ownerMemberMarkerPrefix + "inc": "User", "inc": "BOB_INCOME", "login": "bob",
	}}, denied, noUserFieldDenied).(map[string]any)
	if s := mustJSON(keep); !strings.Contains(s, "BOB_INCOME") {
		t.Fatalf("allowed user's income wrongly redacted: %s", s)
	}
}

// sponsorablePublicFields are the Sponsorable fields that are NOT owner-private — public sponsor-listing
// flags and VIEWER-relative relationship fields (about the requesting custodian, not the navigated owner).
var sponsorablePublicFields = map[string]bool{
	"hasSponsorsListing": true, "isSponsoredBy": true, "isSponsoringViewer": true, "sponsorsListing": true,
	"sponsorshipForViewerAsSponsor": true, "sponsorshipForViewerAsSponsorable": true,
	"viewerCanSponsor": true, "viewerIsSponsoring": true,
}

// TestR28_SponsorableFieldsClassified is the INVERTED coverage guard (round-30): rather than a name
// heuristic ("ends in InCents", which missed sponsorshipsAsMaintainer/Newsletters/sponsors), assert EVERY
// Sponsorable field is classified as either owner-private (userPrivateFields, nulled for a denied user) or
// justified-public (sponsorablePublicFields). Unclassified Sponsorable fields in the embedded schema fail the build instead of silently leaking.
func TestR28_SponsorableFieldsClassified(t *testing.T) {
	s, _ := Load()
	sp := s.schema.Types["Sponsorable"]
	if sp == nil {
		t.Skip("no Sponsorable interface")
	}
	for _, f := range sp.Fields {
		if !userPrivateFields[f.Name] && !sponsorablePublicFields[f.Name] {
			t.Errorf("Sponsorable field %q is unclassified — add it to userPrivateFields (nulled for a denied "+
				"user) or, if genuinely public, to sponsorablePublicFields", f.Name)
		}
	}
}
