package restfilter

import (
	"strings"
	"testing"
)

// TestR44_ProjectItemContentScrubbed pins round-44 Finding 2: the single-item GET/PATCH project endpoint
// scrubs the linked Issue/PR `content` of a denied repo (the write path runs only Content/Write scrub, no
// Pass body-scan), keeping a repo-less draft item intact.
func TestR44_ProjectItemContentScrubbed(t *testing.T) {
	locs := ContentScrubFields("/orgs/acme/projectsV2/3/items/9")
	if len(locs) == 0 {
		t.Fatal("project item singleton not registered for content scrub")
	}
	authorized := func(or string) bool { return or != "acme/secret" }
	body := []byte(`{"id":9,"content":{"repository":{"full_name":"acme/secret"},"title":"SECRET_ISSUE","body":"x"}}`)
	out, ok := ScrubDeniedContent(body, locs, authorized)
	if !ok {
		t.Fatal("content scrub failed")
	}
	if strings.Contains(string(out), "SECRET_ISSUE") {
		t.Fatalf("F2: denied repo's linked content not nulled on the item endpoint: %s", out)
	}
	// a repo-less draft item is KEPT (null-on-denied, not fail-closed).
	draft := []byte(`{"id":10,"content":{"title":"MY_DRAFT","body":"y"}}`)
	out2, ok := ScrubDeniedContent(draft, locs, authorized)
	if !ok {
		t.Fatal("draft scrub failed")
	}
	if !strings.Contains(string(out2), "MY_DRAFT") {
		t.Fatalf("F2: a repo-less draft item was wrongly dropped: %s", out2)
	}
}
