package gqlfilter

import (
	"strings"
	"testing"
)

// TestR42_UserOwnedAmbientNarrowed pins the round-42 F1/F3/F4 fix: the user-owned sentinel that suppresses
// the ownerSelfMarker fail-close must thread ONLY into a User's userPrivateField children (its OWN projects/
// sponsors, gated by the User markers), NOT into every child. Content reached through a NON-private User
// field or a cross-owner edge is gated by no User marker and must fail closed. Before the fix, blanket-
// threading kept the custodian's Sponsors financials (sponsorsListing) and cross-owner org ProjectV2 boards.
func TestR42_UserOwnedAmbientNarrowed(t *testing.T) {
	allow := func(string, string) bool { return false } // nothing base-denied
	noUP := noUserFieldDenied
	upDenied := func(cat string) bool { return cat == "user_private" }

	selfProject := func(secret string) map[string]any {
		return map[string]any{ownerSelfMarkerPrefix + resourceCode("projects"): "ProjectV2", "title": secret, "id": "PV_x"}
	}

	// (F3/F4) cross-owner edge: a NON-private User field (issues) reaching a self-marked org ProjectV2 →
	// fail closed (inherited ambient "" at the non-private child, NOT the user-owned sentinel).
	crossOwner := map[string]any{
		userMarkerAlias: "octocat",
		"issues": map[string]any{"nodes": []any{map[string]any{
			"projectItems": map[string]any{"nodes": []any{map[string]any{
				"project": selfProject("CROSS_OWNER_BOARD"),
			}}},
		}}},
	}
	if js := mustJSON(RedactDeniedOwnerPrivate(crossOwner, allow, noUP)); strings.Contains(js, "CROSS_OWNER_BOARD") {
		t.Fatalf("F3/F4: org ProjectV2 via User.issues cross-owner edge not fail-closed: %s", js)
	}

	// (F1) sponsorsListing is now a userPrivateField: the realistic augmented shape carries its user_private
	// marker, so it is nulled under user_private-DENIED (closes the custodian Sponsors-financials leak)…
	slBody := func() map[string]any {
		return map[string]any{
			userMarkerAlias:                   "octocat",
			userOwnContentMarkerPrefix + "sl": "SponsorsListing",
			"sl": map[string]any{
				ownerSelfMarkerPrefix + resourceCode("sponsors"): "SponsorsListing",
				"contactEmailAddress":                            "SECRET_STRIPE_EMAIL", "id": "SL_1",
			},
		}
	}
	if js := mustJSON(RedactDeniedOwnerPrivate(slBody(), allow, upDenied)); strings.Contains(js, "SECRET_STRIPE_EMAIL") {
		t.Fatalf("F1: custodian sponsorsListing not nulled under user_private-denied: %s", js)
	}
	// …and KEPT under user_private-ALLOWED (the custodian's own self-view is not over-redacted).
	if js := mustJSON(RedactDeniedOwnerPrivate(slBody(), allow, noUP)); !strings.Contains(js, "SECRET_STRIPE_EMAIL") {
		t.Fatalf("F1: custodian sponsorsListing wrongly nulled under user_private-allowed (over-redaction): %s", js)
	}
}

// TestR42_SelfMarkerFailCloseNullsEverything pins the round-42 F5 fix AS HARDENED by round-43 F3: the
// owner-owned-content self-marker fail-close nulls EVERY non-marker field by response key — the former
// {__typename,id} keep-set was alias-bypassable (`id: <secret-scalar>` aliased a secret to a kept key), so
// url/resourcePath/databaseId/title AND id are all nulled; a fail-closed item carries no data.
func TestR42_SelfMarkerFailCloseNullsEverything(t *testing.T) {
	proj := map[string]any{
		ownerSelfMarkerPrefix + resourceCode("projects"): "ProjectV2",
		"title":        "SECRET_BOARD",
		"url":          "https://github.com/orgs/acme/projects/42",
		"resourcePath": "/orgs/acme/projects/42",
		"databaseId":   42,
		"id":           "PVT_secret",
	}
	js := mustJSON(RedactDeniedOwnerPrivate(proj, func(string, string) bool { return false }, noUserFieldDenied))
	for _, leaked := range []string{"github.com", "acme", "projects/42", "SECRET_BOARD", "PVT_secret"} {
		if strings.Contains(js, leaked) {
			t.Fatalf("F5/F3: fail-closed ProjectV2 leaked %q (every field must be nulled by key): %s", leaked, js)
		}
	}
}

// TestR43_SelfMarkerKeepSetAliasImmune pins round-43 F3: a client aliasing a SECRET scalar to a former
// keep-set key (`id: title`) must NOT survive the self-marker fail-close — nulling is by response KEY, and
// there is no keep-set, so the aliased secret is nulled like any other field.
func TestR43_SelfMarkerKeepSetAliasImmune(t *testing.T) {
	// response shape of `project { id: title  __typename: shortDescription }` reaching the fail-close with no
	// owner ancestor: the response keys are id/__typename, the VALUES are the secret board scalars.
	proj := map[string]any{
		ownerSelfMarkerPrefix + resourceCode("projects"): "ProjectV2",
		"id":         "SECRET_TITLE_ALIASED_TO_ID",
		"__typename": "SECRET_DESC_ALIASED_TO_TYPENAME",
	}
	js := mustJSON(RedactDeniedOwnerPrivate(proj, func(string, string) bool { return false }, noUserFieldDenied))
	for _, leaked := range []string{"SECRET_TITLE_ALIASED_TO_ID", "SECRET_DESC_ALIASED_TO_TYPENAME"} {
		if strings.Contains(js, leaked) {
			t.Fatalf("F3: alias to a former keep-set key dodged the fail-close null: %s", js)
		}
	}
}
