package classifier

import (
	"testing"

	"better-gh/internal/gqlfilter"
)

func r35HasCategory(scopes []Scope, cat string) bool {
	for _, s := range scopes {
		if s.UnscopedCategory == cat {
			return true
		}
	}
	return false
}

// TestR35_UsersPathPrivateSubtreesDenied pins the round-35 finding-1 fix: the authenticated-only
// /users/{username}/<sub> subtrees (settings/billing, projectsV2, docker, installation, copilot-spaces)
// resolve to the CUSTODIAN's OWN private data when {username} is the custodian's login (the proxy is authed
// as the custodian), so they must classify to the un-floored "user_private" category — denied under
// default-deny and NOT granted by a bare `[[org]] name="<custodian-login>"` read rule (the documented
// repo-enumeration grant). The PUBLIC third-person subtrees (repos/keys/gpg_keys/…) must NOT be un-floored,
// so public reads and restfilter-redacted feeds keep working.
func TestR35_UsersPathPrivateSubtreesDenied(t *testing.T) {
	private := []string{
		"/users/octocat/settings/billing/usage",
		"/users/octocat/settings/billing/usage/summary",
		"/users/octocat/settings/billing/ai_credit/usage",
		"/users/octocat/settings/billing/premium_request/usage",
		"/users/octocat/projectsV2",
		"/users/octocat/projectsV2/5/items",
		"/users/octocat/docker/conflicts",
		"/users/octocat/installation",
		"/users/octocat/copilot-spaces",
		"/users/octocat/copilot-spaces/3/resources",
	}
	for _, p := range private {
		r := Classify("GET", p, nil)
		if !r35HasCategory(r.AllScopes(), "user_private") {
			t.Errorf("GET %s must classify to user_private (custodian-private), got %+v", p, r.AllScopes())
		}
		// And it must NOT be satisfiable by a bare org-read grant on the path login (Org scope absent).
		if classifierScopesOrgR35(r, "octocat") {
			t.Errorf("GET %s wrongly emits an org scope for the path login — a bare [[org]] read grant would leak it: %+v", p, r.AllScopes())
		}
	}
	public := []string{
		"/users/octocat",
		"/users/octocat/repos",
		"/users/octocat/keys",
		"/users/octocat/gpg_keys",
		"/users/octocat/ssh_signing_keys",
		"/users/octocat/followers",
		"/users/octocat/orgs",
		"/users/octocat/starred",
		"/users/octocat/events",
	}
	for _, p := range public {
		r := Classify("GET", p, nil)
		if r35HasCategory(r.AllScopes(), "user_private") {
			t.Errorf("GET %s wrongly un-floored to user_private (it is a public third-person view): %+v", p, r.AllScopes())
		}
	}
}

func classifierScopesOrgR35(r Result, org string) bool {
	for _, s := range r.AllScopes() {
		if s.Org == org {
			return true
		}
	}
	return false
}

// r35ViewerRelativePublic are the viewerPrivateFieldCategory User fields intentionally NOT response-nulled on
// a NAVIGATED User — now EMPTY. (sponsorshipForViewerAs* were here until round-40 F3/F4/F8 showed they leak
// the custodian's OWN tier price / payment source; sponsorsListing was here until round-42 F1 showed the
// OWNER's own listing exposes activeStripeConnectAccount/contactEmailAddress — both are now in
// gqlfilter.userPrivateFields, gated on user_private on User AND Organization nav paths.) Kept as an
// (empty) exemption hook so a future justified viewer-relative-public field has a documented home.
var r35ViewerRelativePublic = map[string]bool{}

// TestR35_UserPrivateFieldSetsCoupled is the cross-package coupling guard the round-31/34 work lacked: it
// asserts that every field the classifier treats as owner-private at the viewer/user(login:) front gate
// (viewerPrivateFieldCategory) and that the User type actually declares is ALSO in gqlfilter.userPrivateFields
// — the response-side set that nulls a navigated User's private fields. Without this coupling the two sets
// drifted (round-35: the classifier gated ~33 fields, gqlfilter nulled only 11 sponsors fields), so the
// custodian's email/SECRET-gists/savedReplies/keys leaked via an author/uploadedBy edge that bypasses the
// front gate. A schema refresh or future round that adds a private viewer field to one side now fails the
// build unless it is added to BOTH (or justified as viewer-relative-public).
func TestR35_UserPrivateFieldSetsCoupled(t *testing.T) {
	s, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	u := gqlfilter.SchemaType(s, "User")
	if u == nil {
		t.Skip("no User type")
	}
	userField := map[string]bool{}
	for _, f := range u.Fields {
		userField[f.Name] = true
	}
	resp := map[string]bool{}
	for _, f := range gqlfilter.UserPrivateFields() {
		resp[f] = true
	}
	for field := range viewerPrivateFieldCategory {
		if !userField[field] || r35ViewerRelativePublic[field] {
			continue // viewer-only field (not a navigable User field) or a justified viewer-relative-public field
		}
		if !resp[field] {
			t.Errorf("User field %q is owner-private at the front gate (viewerPrivateFieldCategory) but NOT in "+
				"gqlfilter.userPrivateFields — a navigated author/owner/...on User edge leaks it past the front "+
				"gate; add it to userPrivateFields (and userGistFields if it is gist-category)", field)
		}
	}
	// The gist-category coupling: every gist field the classifier routes to "gists" that is also a navigable
	// User private field must be marked gist-category on the response side too.
	for field, cat := range viewerPrivateFieldCategory {
		if cat == "gists" && userField[field] && resp[field] && !gqlfilter.UserGistField(field) {
			t.Errorf("User gist field %q is gated on the gists category at the front gate but gqlfilter.UserGistField "+
				"returns false — it would be gated on user_private on the response side; add it to userGistFields", field)
		}
	}
}
