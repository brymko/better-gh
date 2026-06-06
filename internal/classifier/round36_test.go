package classifier

import "testing"

// TestR36_ViewerPinnableItemsGistGated pins the round-36 finding-3 fix: viewer/user(login:) pinnableItems/
// pinnedItems/itemShowcase surface the custodian's SECRET gists via the PinnableItem (Gist|Repository)
// union, so they must emit the "gists" category and be denied under a default-deny / gists-denied token —
// the parity of viewer{gists}. Before the fix they classified to the floored "user" scope only.
func TestR36_ViewerPinnableItemsGistGated(t *testing.T) {
	has := func(scopes []Scope, cat string) bool {
		for _, s := range scopes {
			if s.UnscopedCategory == cat {
				return true
			}
		}
		return false
	}
	for _, q := range []string{
		`{ viewer { pinnableItems(types:[GIST],first:50){ nodes{ ...on Gist { name description files{ text } } } } } }`,
		`{ viewer { pinnedItems(first:5){ nodes{ ...on Gist { name } } } } }`,
		`{ viewer { itemShowcase { items(first:5){ nodes{ ...on Gist { name } } } } } }`,
		// user(login:) root resolves to the viewer for the custodian's own login (round-34 un-flooring).
		`{ user(login:"octocat"){ pinnableItems(types:[GIST],first:5){ nodes{ ...on Gist { name } } } } }`,
	} {
		r := Classify("POST", "/graphql", []byte(`{"query":`+jsonStr(q)+`}`))
		if !has(r.AllScopes(), "gists") {
			t.Errorf("%s missing the gists gating category (leaks the custodian's pinned SECRET gists): %+v", q, r.AllScopes())
		}
	}
}
