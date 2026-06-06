package restfilter

import (
	"strings"
	"testing"
)

// TestR36_ContentScrubArrayRoot pins the round-36 finding-1 fix: a content-scrub op whose response is a JSON
// ARRAY (the projectsV2 `.../items` LIST) must have each element's denied-repo content nulled. Before the
// fix ScrubDeniedContent descended only an object root, so the array body streamed unchanged AND the op's
// presence in contentRepoScrubOps suppressed the Pass body-scan backstop — leaking the denied repo's linked
// Issue/PR content.
func TestR36_ContentScrubArrayRoot(t *testing.T) {
	deny := func(r string) bool { return r != "victim/secret" }
	body := `[` +
		`{"id":1,"content":{"title":"SECRET_ISSUE","repository":{"full_name":"victim/secret"}}},` +
		`{"id":2,"content":{"title":"PUBLIC_OK","repository":{"full_name":"acme/pub"}}},` +
		`{"id":3,"content":{"title":"DRAFT","body":"d"}}` +
		`]`
	out, ok := ScrubDeniedContent([]byte(body), []string{"content"}, deny)
	if !ok {
		t.Fatal("array content-scrub failed closed unexpectedly")
	}
	s := string(out)
	if strings.Contains(s, "SECRET_ISSUE") || strings.Contains(s, "victim/secret") {
		t.Fatalf("denied repo's linked content not nulled in an array-root response: %s", s)
	}
	if !strings.Contains(s, "PUBLIC_OK") || !strings.Contains(s, "DRAFT") {
		t.Fatalf("allowed item / draft content wrongly nulled in array root: %s", s)
	}
}
