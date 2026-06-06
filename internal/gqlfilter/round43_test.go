package gqlfilter

import (
	"strings"
	"testing"
)

// TestR43_UserOwnedSentinelNonTransitive pins round-43 F1/F2: the userOwnedAmbient sentinel that keeps the
// user's OWN owner-owned content is NON-TRANSITIVE — it suppresses the self-marker fail-close for the user's
// DIRECT owner-owned object (its projectsV2/sponsorshipsAsSponsor reached through a userPrivateField) but is
// reset for that node's children, so a NESTED self-marked owner-owned object (a cross-owner ProjectV2 via
// issue.projectItems.project, the sponsorable's tier.sponsorsListing) fails closed on its own. Before the fix
// the boolean sentinel propagated unchanged through every intermediate and kept the foreign content.
func TestR43_UserOwnedSentinelNonTransitive(t *testing.T) {
	allow := func(string, string) bool { return false } // nothing base-denied; user_private allowed below
	noUP := noUserFieldDenied
	selfMarked := func(res, secret string) map[string]any {
		return map[string]any{ownerSelfMarkerPrefix + resourceCode(res): "X", "title": secret, "id": "node1"}
	}

	// F1: viewer{ projectsV2 { nodes { ...own board scalars... <nested foreign project> } } }.
	// The outer ProjectV2 is the user's own (reached via the projectsV2 userPrivateField marker) → KEPT;
	// the nested self-marked ProjectV2 (a foreign board reached through the board's own subtree) → FAIL CLOSED.
	ownBoard := selfMarked("projects", "MY_OWN_BOARD")
	ownBoard["crossOwner"] = selfMarked("projects", "FOREIGN_BOARD")
	f1 := map[string]any{
		userMarkerAlias:                "octocat",
		ownerMemberMarkerPrefix + "pv": "ProjectV2",
		"pv":                           ownBoard,
	}
	js := mustJSON(RedactDeniedOwnerPrivate(f1, allow, noUP))
	if !strings.Contains(js, "MY_OWN_BOARD") {
		t.Fatalf("F1: the user's OWN top-level board was wrongly fail-closed: %s", js)
	}
	if strings.Contains(js, "FOREIGN_BOARD") {
		t.Fatalf("F1: a nested cross-owner ProjectV2 under the user's own board was NOT fail-closed: %s", js)
	}

	// F2: viewer{ sponsorshipsAsSponsor { nodes { ...own sponsorship... tier { sponsorsListing {...} } } } }.
	// Sponsorship/SponsorsTier/SponsorsListing are all @docsCategory "sponsors" → a contiguous self-marked
	// chain; the sentinel must die at the first node so the sponsorable's listing financials fail closed.
	ownSponsorship := selfMarked("sponsors", "MY_SPONSORSHIP")
	ownSponsorship["tier"] = map[string]any{
		ownerSelfMarkerPrefix + resourceCode("sponsors"): "SponsorsTier",
		"sponsorsListing": map[string]any{
			ownerSelfMarkerPrefix + resourceCode("sponsors"): "SponsorsListing",
			"contactEmailAddress":                            "SPONSORABLE_STRIPE_EMAIL", "id": "sl1",
		},
	}
	f2 := map[string]any{
		userMarkerAlias:                "octocat",
		ownerMemberMarkerPrefix + "sp": "SponsorshipConnection",
		"sp":                           ownSponsorship,
	}
	js2 := mustJSON(RedactDeniedOwnerPrivate(f2, allow, noUP))
	if !strings.Contains(js2, "MY_SPONSORSHIP") {
		t.Fatalf("F2: the user's OWN sponsorship node was wrongly fail-closed: %s", js2)
	}
	if strings.Contains(js2, "SPONSORABLE_STRIPE_EMAIL") {
		t.Fatalf("F2: the sponsorable's cross-owner sponsorsListing financials were NOT fail-closed: %s", js2)
	}
}
