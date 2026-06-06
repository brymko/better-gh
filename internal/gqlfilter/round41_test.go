package gqlfilter

import (
	"strings"
	"testing"
)

// TestR41_TeamsAndSponsorBooleansGated pins the round-41 finding-5 (teams inventory on nav) + finding-2
// (viewer-sponsorship existence bits) response-side fixes.
func TestR41_TeamsAndSponsorBooleansGated(t *testing.T) {
	s, _ := Load()
	// F5: organization{teams} content-marked "teams".
	out, _ := s.Augment(`{ organization(login:"a"){ tm: teams(first:1){ nodes{ name } } } }`)
	if !strings.Contains(out, ownerContentMarkerPrefix+resourceCode("teams")+"__tm") {
		t.Fatalf("org teams not content-marked:\n%s", out)
	}
	// F5 redaction: teams nulled under teams=none (org base-allowed).
	teamsDenied := func(owner, resource string) bool { return owner == "acme" && resource == "teams" }
	teamBody := map[string]any{
		ownerMarkerAlias: "acme",
		ownerContentMarkerPrefix + resourceCode("teams") + "__tm": "Organization",
		"tm": map[string]any{"nodes": []any{map[string]any{"name": "SECRET_TEAM"}}},
	}
	if js := mustJSON(RedactDeniedOwnerPrivate(teamBody, teamsDenied, noUserFieldDenied)); strings.Contains(js, "SECRET_TEAM") {
		t.Fatalf("org team inventory not nulled under teams=none on nav: %s", js)
	}

	// F2: viewerIsSponsoring content-marked with the viewer-private sentinel.
	out2, _ := s.Augment(`{ repository(owner:"a",name:"r"){ owner{ ...on Organization{ viewerIsSponsoring } } } }`)
	if !strings.Contains(out2, ownerContentMarkerPrefix+resourceCode(viewerPrivateContentResource)+"__viewerIsSponsoring") {
		t.Fatalf("viewerIsSponsoring not sentinel-marked:\n%s", out2)
	}
	// F2 redaction: nulled under user_private denied (org base-allowed).
	upDenied := func(cat string) bool { return cat == "user_private" }
	boolBody := map[string]any{
		ownerMarkerAlias: "acme",
		ownerContentMarkerPrefix + resourceCode(viewerPrivateContentResource) + "__viewerIsSponsoring": "Organization",
		"viewerIsSponsoring": "SECRET_TRUE",
	}
	if js := mustJSON(RedactDeniedOwnerPrivate(boolBody, func(string, string) bool { return false }, upDenied)); strings.Contains(js, "SECRET_TRUE") {
		t.Fatalf("viewerIsSponsoring not nulled under user_private-denied: %s", js)
	}
}
