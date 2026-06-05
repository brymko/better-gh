package policy

import (
	"testing"

	"better-gh/internal/classifier"
)

// Round-20: a mixed-case org per-resource key (org keys are unvalidated, so a natural casing mistake
// like [org.permissions] Members="none" must still match the lowercase request resource "members"
// rather than silently fail open to base org read).
func TestR20_OrgPerResourceCaseInsensitive(t *testing.T) {
	p := &Policy{
		Org: []OrgRule{{
			Name: "acme", Access: AccessRead,
			Permissions: map[string]Access{"Members": AccessNone}, // mixed case
		}},
	}
	// orgResource() yields lowercase "members" from GET /orgs/acme/members.
	if res := p.Evaluate("", "acme", classifier.Read, "members", ""); res.Allowed {
		t.Fatalf("mixed-case [org.permissions] Members=none must deny a read of members, but it was allowed")
	}
	// A resource the rule does not carve out still falls to base read.
	if res := p.Evaluate("", "acme", classifier.Read, "hooks", ""); !res.Allowed {
		t.Fatalf("uncarved org resource must fall to base read, got deny")
	}
}
