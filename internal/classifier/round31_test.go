package classifier

import (
	"testing"

	"better-gh/internal/gqlfilter"
	"github.com/vektah/gqlparser/v2/ast"
)

// TestR31_ViewerPrivateGated pins the round-31 fix: viewer's owner-private sub-resources are gated
// (gists → "gists", others → "user_private") so a default-deny token can't read the custodian's private
// data, while viewer identity stays floored "user".
func TestR31_ViewerPrivateGated(t *testing.T) {
	has := func(scopes []Scope, cat string) bool {
		for _, s := range scopes {
			if s.UnscopedCategory == cat {
				return true
			}
		}
		return false
	}
	for q, cat := range map[string]string{
		`{ viewer { gists(privacy:SECRET,first:1){ nodes{ name } } } }`:   "gists",
		`{ viewer { organizations(first:1){ nodes{ login } } } }`:         "user_private",
		`{ viewer { enterprises(first:1){ nodes{ slug } } } }`:            "user_private",
		`{ viewer { projectsV2(first:1){ nodes{ title } } } }`:            "user_private",
		`{ viewer { savedReplies(first:1){ nodes{ body } } } }`:           "user_private",
		`{ viewer { sponsorshipsAsMaintainer(first:1){ nodes{ id } } } }`: "user_private",
	} {
		r := Classify("POST", "/graphql", []byte(`{"query":`+jsonStr(q)+`}`))
		if !has(r.AllScopes(), cat) {
			t.Errorf("%s missing gating category %q: %+v", q, cat, r.AllScopes())
		}
	}
	r := Classify("POST", "/graphql", []byte(`{"query":"{ viewer { login } }"}`))
	if has(r.AllScopes(), "user_private") || has(r.AllScopes(), "gists") {
		t.Errorf("viewer{login} wrongly gated: %+v", r.AllScopes())
	}
}

// ownerPrivateDocsCategories are the @docsCategory names whose User-reachable element types carry
// owner-PRIVATE data (the custodian's gists, sponsors, orgs, enterprise admin, projects, migrations).
// The coverage guard derives the owner-private element set from this category set rather than a
// hand-listed type allowlist, so private element types in the embedded schema are caught without editing a type list.
// TestR31_ViewerPrivateFieldCoverage is the derived coverage guard: every User field whose return element
// carries an owner-private @docsCategory must be in viewerPrivateFieldCategory, so private viewer collections in the embedded schema must be covered (round-31; round-32 re-based on @docsCategory after the hand-listed type set missed GistComment).
func TestR31_ViewerPrivateFieldCoverage(t *testing.T) {
	s, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	def := gqlfilter.SchemaType(s, "User")
	if def == nil {
		t.Skip("no User type")
	}
	unwrap := func(tp *ast.Type) string {
		for tp.Elem != nil {
			tp = tp.Elem
		}
		return tp.Name()
	}
	// Owner-private-CONTENT @docsCategory names (correct schema spellings). The node-id "users" category is
	// deliberately EXCLUDED: it is MIXED — owner-private (SavedReply/email/keys, hand-listed in
	// viewerPrivateFieldCategory) AND public profile (UserStatus/PinnableItem/followers/contributionsCollection,
	// correctly NOT gated). The unambiguously-private content categories below ARE all type-derivable.
	ownerPrivateContentCategories := map[string]bool{
		"gists": true, "sponsors": true, "orgs": true, "enterprise-admin": true,
		"projects": true, "projects-classic": true, "migrations": true,
	}
	docsCategoryOf := func(typeName string) string {
		d := gqlfilter.SchemaType(s, typeName)
		if d == nil {
			return ""
		}
		if dir := d.Directives.ForName("docsCategory"); dir != nil {
			if a := dir.Arguments.ForName("name"); a != nil && a.Value != nil {
				return a.Value.Raw
			}
		}
		return ""
	}
	// privateCat reports the owner-private content @docsCategory of a type, OR — if the type is a union/
	// interface — of any of its concrete members. A private element can sit one structural hop deep inside a
	// union/interface member of a "users"-category container field (pinnableItems → PinnableItem(union) →
	// Gist), which the single-nodes unwrap alone misses (round-36: the viewer{pinnableItems}{...on Gist}
	// SECRET-gist leak). Descending union members forces such a field into the gate.
	privateCat := func(typeName string) string {
		if ownerPrivateContentCategories[docsCategoryOf(typeName)] {
			return docsCategoryOf(typeName)
		}
		if d := gqlfilter.SchemaType(s, typeName); d != nil && (d.Kind == ast.Union || d.Kind == ast.Interface) {
			for _, m := range gqlfilter.TypeMembers(s, typeName) {
				if ownerPrivateContentCategories[docsCategoryOf(m)] {
					return docsCategoryOf(m)
				}
			}
		}
		return ""
	}
	for _, f := range def.Fields {
		rt := unwrap(f.Type)
		elem := rt
		if d := gqlfilter.SchemaType(s, rt); d != nil {
			for _, sub := range d.Fields {
				if sub.Name == "nodes" {
					elem = unwrap(sub.Type)
				}
			}
		}
		if cat := privateCat(elem); cat != "" && viewerPrivateFieldCategory[f.Name] == "" {
			t.Errorf("viewer/User field %q returns owner-private %q (@docsCategory %q, possibly via a union/"+
				"interface member) but is not in viewerPrivateFieldCategory — it leaks the custodian's private "+
				"data; gate it", f.Name, elem, cat)
		}
	}
}

// TestR32_GistCommentsGated pins the round-32 fix: viewer{gistComments} (a gists-category connection
// returning GistComment) is gated to "gists" like viewer{gists}, so a default-deny token with no gists
// grant cannot read the custodian's gist-comment bodies — including comments on SECRET gists.
func TestR32_GistCommentsGated(t *testing.T) {
	has := func(scopes []Scope, cat string) bool {
		for _, s := range scopes {
			if s.UnscopedCategory == cat {
				return true
			}
		}
		return false
	}
	q := `{ viewer { gistComments(first:50){ nodes{ body bodyText author{login} gist{ name description isPublic } } } } }`
	r := Classify("POST", "/graphql", []byte(`{"query":`+jsonStr(q)+`}`))
	if !has(r.AllScopes(), "gists") {
		t.Fatalf("viewer{gistComments} not gated to gists category: %+v", r.AllScopes())
	}
}
