package proxy

import "testing"

// TestR42_PathOwnerForScan pins the round-42 F6 fix: a /users/{username}/… Pass op carries the custodian's
// OWN repos by bare name but the classifier sets neither Owner nor Org (user_private category), so the body
// scan's org-gated bare-name branch was skipped. pathOwnerForScan recovers {username} as the qualifying
// owner so bare repo names (the enhanced-billing repositoryName) are authorized.
func TestR42_PathOwnerForScan(t *testing.T) {
	cases := map[string]string{
		"/users/octocat/settings/billing/usage": "octocat",
		"/users/octocat/copilot-spaces":         "octocat",
		"/orgs/acme/settings/billing/usage":     "", // /orgs sets classified.Org already; no fallback needed
		"/user/repos":                           "",
		"/repos/octocat/secret/issues":          "",
		"/users":                                "",
	}
	for path, want := range cases {
		if got := pathOwnerForScan(path); got != want {
			t.Errorf("pathOwnerForScan(%q) = %q, want %q", path, got, want)
		}
	}
}
