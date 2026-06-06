package gqlfilter

import (
	"strings"
	"testing"
)

// TestR29_ConcreteAndInlineUserMarked pins the round-29 fix: a denied User's owner-private fields are marked
// (and redacted) when reached by CONCRETE navigation or via an `... on User` inline fragment — not only as
// an interface common field (round-28) — while a User reached without a private field is never marked.
func TestR29_ConcreteAndInlineUserMarked(t *testing.T) {
	s, _ := Load()
	cases := []struct {
		name, query string
		marked      bool
	}{
		{"concrete-User-nav", `{ repository(owner:"a",name:"r"){ release(tagName:"v"){ author{ login estimatedNextSponsorsPayoutInCents } } } }`, true},
		{"inline-fragment-User-on-union", `{ user(login:"a"){ sponsorsActivities(first:1){ nodes{ sponsor{ ... on User { monthlyEstimatedSponsorsIncomeInCents } } } } } }`, true},
		{"interface-common-field", `{ organization(login:"a"){ sponsorshipsAsSponsor(first:1){ nodes{ sponsorable{ totalSponsorshipAmountAsSponsorInCents } } } } }`, true},
		{"concrete-User-no-private-field", `{ repository(owner:"a",name:"r"){ release(tagName:"v"){ author{ login name } } } }`, false},
	}
	for _, c := range cases {
		out, err := s.Augment(c.query)
		if err != nil {
			t.Fatalf("%s: augment err: %v", c.name, err)
		}
		if got := strings.Contains(out, userMarkerAlias); got != c.marked {
			t.Errorf("%s: user-marked=%v want %v\n%s", c.name, got, c.marked, out)
		}
	}

	// end-to-end redaction: a denied user reached by concrete nav has its private field nulled, login kept.
	red := RedactDeniedOwnerPrivate(map[string]any{"author": map[string]any{
		userMarkerAlias: "victim", ownerMemberMarkerPrefix + "estimatedNextSponsorsPayoutInCents": "User",
		"estimatedNextSponsorsPayoutInCents": "VICTIM_PAYOUT", "login": "victim",
	}}, func(o, _ string) bool { return o == "victim" }, noUserFieldDenied).(map[string]any)
	if s := mustJSON(red); strings.Contains(s, "VICTIM_PAYOUT") {
		t.Fatalf("denied user's payout leaked via concrete nav: %s", s)
	}
}

// TestR29_UserMarkerInjectionInvariant is the marker-INJECTION drift guard (the meta-fix): for every field
// whose unwrapped type is concrete User and every interface/union with a User possible type, selecting a
// userPrivateField — directly AND inside `... on User` — must yield the user marker in the augmented query.
func TestR29_UserMarkerInjectionInvariant(t *testing.T) {
	s, _ := Load()
	// concrete: a representative concrete `: User` field path
	for _, q := range []string{
		`{ repository(owner:"a",name:"r"){ release(tagName:"v"){ author{ sponsorsActivities(first:1){ nodes{ __typename } } } } } }`,
		`{ repository(owner:"a",name:"r"){ release(tagName:"v"){ author{ ... on User { lifetimeReceivedSponsorshipValues(first:1){ nodes{ __typename } } } } } } }`,
	} {
		out, err := s.Augment(q)
		if err != nil {
			t.Fatalf("augment err for %q: %v", q, err)
		}
		if !strings.Contains(out, userMarkerAlias) {
			t.Errorf("user private field not marker-injected for query %q:\n%s", q, out)
		}
	}
}
