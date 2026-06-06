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

// TestR31_ViewerPrivateFieldCoverage is the derived drift guard: every User field whose return element is
// an owner-private type (Gist/ProjectV2/SavedReply/Sponsorship/SponsorsActivity) must be in
// viewerPrivateFieldCategory, so a schema refresh adding a new private viewer collection fails the build.
func TestR31_ViewerPrivateFieldCoverage(t *testing.T) {
	s, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	ownerPrivateElem := map[string]bool{
		"Gist": true, "ProjectV2": true, "SavedReply": true, "Sponsorship": true, "SponsorsActivity": true,
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
		if ownerPrivateElem[elem] && viewerPrivateFieldCategory[f.Name] == "" {
			t.Errorf("viewer/User field %q returns owner-private %q but is not in viewerPrivateFieldCategory "+
				"— it leaks the custodian's private data; gate it", f.Name, elem)
		}
	}
}
