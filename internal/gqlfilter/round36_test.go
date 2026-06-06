package gqlfilter

import (
	"strings"
	"testing"
)

// TestR36_AliasedGistFieldGatedByCategory pins the round-36 fix: a navigated User's gist field selected with
// a client ALIAS (mine: gists) must still be gated on the "gists" category, not downgraded to "user_private".
// Before the fix the per-field marker was keyed on the alias and UserGistField(alias) missed, so an aliased
// SECRET gist streamed under a user_private-granted/gists-denied policy. The category is now carried by the
// marker PREFIX (set from the schema field name at augment time), so it is alias-immune.
func TestR36_AliasedGistFieldGatedByCategory(t *testing.T) {
	s, _ := Load()
	out, err := s.Augment(`{ repository(owner:"a",name:"r"){ pullRequests(first:1){ nodes{ author{ ... on User {
		mine: gists(first:50, privacy:SECRET){ nodes{ name } } } } } } } }`)
	if err != nil {
		t.Fatal(err)
	}
	// the marker for the ALIASED gist must carry the gist category via the prefix, keyed on the alias `mine`.
	if !strings.Contains(out, userGistMarkerPrefix+"mine") {
		t.Fatalf("aliased gist field not gist-marked (would downgrade to user_private):\n%s", out)
	}
	if strings.Contains(out, ownerMemberMarkerPrefix+"mine") {
		t.Fatalf("aliased gist field marked as user_private — alias downgrade not fixed:\n%s", out)
	}

	// redaction: user_private GRANTED, gists DENIED, owner login allowed → the aliased gist must be nulled.
	ownerAllowed := func(string, string) bool { return false }
	gistsDenied := func(cat string) bool { return cat == "gists" }
	red := RedactDeniedOwnerPrivate(map[string]any{"author": map[string]any{
		userMarkerAlias:               "octocat",
		userGistMarkerPrefix + "mine": "User",
		"mine":                        map[string]any{"nodes": []any{map[string]any{"name": "AWS_SECRET_GIST"}}},
		"login":                       "octocat",
	}}, ownerAllowed, gistsDenied).(map[string]any)
	if js := mustJSON(red); strings.Contains(js, "AWS_SECRET_GIST") {
		t.Fatalf("aliased gist survived gists-denied (user_private granted) — alias downgrade leak: %s", js)
	}
}
