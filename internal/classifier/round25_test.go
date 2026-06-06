package classifier

import (
	"testing"

	"better-gh/internal/gqlfilter"
)

// TestR25_OrgMemberResponseFieldsInSync is the anti-drift guard for the round-25 member-nav fix: every
// Organization field the classifier maps to the "members" per-resource key MUST be in the response
// filter's redaction set (gqlfilter.OrgMemberResponseFields), and vice versa — otherwise a member field
// scoped request-side would not be redacted response-side (or a redacted field would have no request gate).
func TestR25_OrgMemberResponseFieldsInSync(t *testing.T) {
	requestMembers := map[string]bool{}
	for field, res := range gqlOrgFieldToResource {
		if res == "members" {
			requestMembers[field] = true
		}
	}
	responseFields := map[string]bool{}
	for _, f := range gqlfilter.OrgMemberFieldNames() {
		responseFields[f] = true
	}
	for f := range requestMembers {
		if !responseFields[f] {
			t.Errorf("Organization.%s maps to \"members\" in gqlOrgFieldToResource but is NOT in "+
				"gqlfilter.OrgMemberResponseFields — it is request-scoped but not response-redacted (nav bypass)", f)
		}
	}
	for f := range responseFields {
		if !requestMembers[f] {
			t.Errorf("gqlfilter.OrgMemberResponseFields has %q but it is not a gqlOrgFieldToResource "+
				"\"members\" key — response-redacted with no request-side gate (drift)", f)
		}
	}
}
