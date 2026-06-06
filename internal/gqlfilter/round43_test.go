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

	// F1: viewer{ projectsV2 { nodes { ...own board scalars... <nested foreign project> } } }. projectsV2 is an
	// OWN-content private field (userOwnContentMarkerPrefix) so the outer ProjectV2 is KEPT; the nested
	// self-marked ProjectV2 (a foreign board reached through the board's own subtree) → FAIL CLOSED (the
	// round-43 non-transitive reset).
	ownBoard := selfMarked("projects", "MY_OWN_BOARD")
	ownBoard["crossOwner"] = selfMarked("projects", "FOREIGN_BOARD")
	f1 := map[string]any{
		userMarkerAlias:                   "octocat",
		userOwnContentMarkerPrefix + "pv": "ProjectV2",
		"pv":                              ownBoard,
	}
	js := mustJSON(RedactDeniedOwnerPrivate(f1, allow, noUP))
	if !strings.Contains(js, "MY_OWN_BOARD") {
		t.Fatalf("F1: the user's OWN top-level board was wrongly fail-closed: %s", js)
	}
	if strings.Contains(js, "FOREIGN_BOARD") {
		t.Fatalf("F1: a nested cross-owner ProjectV2 under the user's own board was NOT fail-closed: %s", js)
	}
}
