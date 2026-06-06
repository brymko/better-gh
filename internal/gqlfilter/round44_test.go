package gqlfilter

import (
	"strings"
	"testing"

	"github.com/vektah/gqlparser/v2/ast"
)

// TestR44_SentinelNotThreadedThroughEntityField pins round-44 Finding 1: the userOwnedAmbient sentinel is
// threaded ONLY into a User's OWN-content private fields (projectsV2/sponsorsListing → userOwnContentMarkerPrefix),
// NOT into an entity-returning private field (sponsoring/sponsors → foreign Users). So a cross-owner self-marked
// ProjectV2 reached through a foreign-User carrier (viewer{sponsoring{nodes{...on User{issues{…project}}}}})
// fails closed, while the user's OWN board is kept.
func TestR44_SentinelNotThreadedThroughEntityField(t *testing.T) {
	allow := func(string, string) bool { return false }
	noUP := noUserFieldDenied

	// sponsoring is NOT an own-content field → ownerMemberMarkerPrefix → NO sentinel → the cross-owner
	// ProjectV2 deep under the foreign sponsorable User fails closed.
	carrier := map[string]any{
		userMarkerAlias:                "octocat",
		ownerMemberMarkerPrefix + "sp": "SponsorConnection",
		"sp": map[string]any{"nodes": []any{map[string]any{ // foreign sponsorable User
			"issues": map[string]any{"nodes": []any{map[string]any{
				"projectItems": map[string]any{"nodes": []any{map[string]any{
					"project": map[string]any{
						ownerSelfMarkerPrefix + resourceCode("projects"): "ProjectV2",
						"title": "FOREIGN_ORG_BOARD", "id": "p1",
					},
				}}},
			}}},
		}}},
	}
	if js := mustJSON(RedactDeniedOwnerPrivate(carrier, allow, noUP)); strings.Contains(js, "FOREIGN_ORG_BOARD") {
		t.Fatalf("Finding 1: cross-owner ProjectV2 via a non-own-content private field (sponsoring) not fail-closed: %s", js)
	}

	// own-content field still keeps the user's own board (no regression).
	own := map[string]any{
		userMarkerAlias:                   "octocat",
		userOwnContentMarkerPrefix + "pv": "ProjectV2",
		"pv": map[string]any{
			ownerSelfMarkerPrefix + resourceCode("projects"): "ProjectV2",
			"title": "MY_BOARD", "id": "p2",
		},
	}
	if js := mustJSON(RedactDeniedOwnerPrivate(own, allow, noUP)); !strings.Contains(js, "MY_BOARD") {
		t.Fatalf("Finding 1: the user's OWN board (own-content field) was wrongly fail-closed: %s", js)
	}
}

// TestR44_PrivateFieldMarkerRouting pins that Augment routes an OWN-content private field to
// userOwnContentMarkerPrefix (carries the sentinel) and an ENTITY-returning private field to
// ownerMemberMarkerPrefix (does NOT), so the redaction split above is actually fed by the augmenter.
func TestR44_PrivateFieldMarkerRouting(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Augment(`{ viewer { projectsV2(first:1){ nodes { title } } } }`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, userOwnContentMarkerPrefix) {
		t.Fatalf("viewer.projectsV2 (own-content) not marked with userOwnContentMarkerPrefix:\n%s", out)
	}
	out2, err := s.Augment(`{ viewer { sponsoring(first:1){ totalCount } } }`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out2, userOwnContentMarkerPrefix) {
		t.Fatalf("viewer.sponsoring (entity-returning) was wrongly own-content-marked — it would carry the sentinel:\n%s", out2)
	}
}

// TestR44_UserOwnContentFieldsCoupled is the derived guard: every userOwnContentField must (a) be a
// userPrivateField (gated user_private) and (b) resolve (through a Connection's nodes) to an owner-owned
// CONTENT type the augmenter self-marks — so a field whose value is NOT the user's own self-marked content
// cannot be added to userOwnContentFields and silently carry the sentinel into a foreign subtree.
func TestR44_UserOwnContentFieldsCoupled(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	u := s.schema.Types["User"]
	if u == nil {
		t.Skip("no User type")
	}
	fieldType := func(def *ast.Definition, name string) *ast.Type {
		for _, f := range def.Fields {
			if f.Name == name {
				return f.Type
			}
		}
		return nil
	}
	for f := range userOwnContentFields {
		if !userPrivateFields[f] {
			t.Errorf("userOwnContentField %q must also be a userPrivateField (gated user_private)", f)
		}
		ft := fieldType(u, f)
		if ft == nil {
			t.Errorf("userOwnContentField %q is not a field on the User type", f)
			continue
		}
		named := ft.Name()
		if def := s.schema.Types[named]; def != nil { // unwrap a Connection to its node element type
			if nt := fieldType(def, "nodes"); nt != nil {
				named = nt.Name()
			}
		}
		if s.ownerOwnedContentResource[named] == "" {
			t.Errorf("userOwnContentField %q resolves to type %q which is NOT an owner-owned content "+
				"(self-marked) type — it must not carry the userOwnedAmbient sentinel; remove it from "+
				"userOwnContentFields", f, named)
		}
	}
}
