package classifier

import "testing"

// TestR34_UserRootPrivateFieldParity pins the round-34 fix and is the derived coupling guard the
// round-31 work lacked: every owner-private field the `viewer` root gates MUST also be gated when the
// SAME field is reached via the `user(login:)` and `repositoryOwner(login:){ ... on User }` roots.
//
// Why: user(login:"<custodian>") and repositoryOwner(login:"<custodian>") resolve to the authenticated
// viewer, so GitHub returns the custodian's OWN owner-private data (private email, SECRET gists, saved
// replies, orgs/enterprises/projectsV2/keys/social/2FA). Before round-34 these roots scoped the User type
// only through gqlOrgResources (the 8 member/team keys); every other private field degraded to one base
// org-read scope, so a token granting base read to the custodian's own login read all of it. This guard
// iterates viewerPrivateFieldCategory itself, so every private viewer field in the embedded schema
// (required to be in the map by TestR31_ViewerPrivateFieldCoverage) is automatically asserted to
// be gated on the user(login:) path too — the request and viewer sides cannot diverge.
func TestR34_UserRootPrivateFieldParity(t *testing.T) {
	has := func(scopes []Scope, cat string) bool {
		for _, s := range scopes {
			if s.UnscopedCategory == cat {
				return true
			}
		}
		return false
	}
	for field, cat := range viewerPrivateFieldCategory {
		// Reached directly under user(login:) (the root IS a User).
		q1 := `{ user(login:"octocat"){ ` + field + ` } }`
		r1 := Classify("POST", "/graphql", []byte(`{"query":`+jsonStr(q1)+`}`))
		if !has(r1.AllScopes(), cat) {
			t.Errorf("user(login:){ %s } missing gating category %q (leaks custodian's private data): %+v",
				field, cat, r1.AllScopes())
		}
		// Reached via the repositoryOwner interface's `... on User { }` (the round-34 PoC path).
		q2 := `{ repositoryOwner(login:"octocat"){ ... on User { ` + field + ` } } }`
		r2 := Classify("POST", "/graphql", []byte(`{"query":`+jsonStr(q2)+`}`))
		if !has(r2.AllScopes(), cat) {
			t.Errorf("repositoryOwner(login:){...on User{ %s }} missing gating category %q: %+v",
				field, cat, r2.AllScopes())
		}
	}
}

// TestR34_UserRootPublicProfileUnaffected pins that the round-34 un-flooring does NOT over-gate a plain
// public-profile read: user(login:){ login name avatarUrl } must NOT acquire a user_private/gists
// category (only the named owner's base scope), so a token with that owner's base read still works.
func TestR34_UserRootPublicProfileUnaffected(t *testing.T) {
	has := func(scopes []Scope, cat string) bool {
		for _, s := range scopes {
			if s.UnscopedCategory == cat {
				return true
			}
		}
		return false
	}
	r := Classify("POST", "/graphql", []byte(`{"query":`+jsonStr(`{ user(login:"octocat"){ login name avatarUrl } }`)+`}`))
	if has(r.AllScopes(), "user_private") || has(r.AllScopes(), "gists") {
		t.Errorf("user(login:){ login name avatarUrl } wrongly gated as owner-private: %+v", r.AllScopes())
	}
}

// TestR34_OrganizationRootNotOverGated pins that the organization(login:) root is EXCLUDED from the
// round-34 un-flooring: an org login can never equal a USER login, so organization(login:) never resolves
// to the viewer. organization(login:){ projectsV2 } must stay base-org-governed (no user_private), so a
// token with that org's base read can still read org metadata.
func TestR34_OrganizationRootNotOverGated(t *testing.T) {
	has := func(scopes []Scope, cat string) bool {
		for _, s := range scopes {
			if s.UnscopedCategory == cat {
				return true
			}
		}
		return false
	}
	r := Classify("POST", "/graphql", []byte(`{"query":`+jsonStr(`{ organization(login:"acme"){ projectsV2(first:1){ nodes{ title } } } }`)+`}`))
	if has(r.AllScopes(), "user_private") || has(r.AllScopes(), "gists") {
		t.Errorf("organization(login:){ projectsV2 } wrongly un-floored to owner-private: %+v", r.AllScopes())
	}
}
