package gqlfilter

import "testing"

// TestR37_CrossRefURIScrubAliasProof pins the round-37 finding-1 fix: the CrossReferencedEvent url/resourcePath
// scrub is VALUE-driven, so a client ALIAS (leak: url) on the scalar cannot dodge it. Before the fix the scrub
// read val["url"]/val["resourcePath"] by exact key, so an aliased scalar streamed the foreign denied repo's URL.
func TestR37_CrossRefURIScrubAliasProof(t *testing.T) {
	deny := func(owner, repo, resource, typename string) Decision {
		if owner == "victim" && repo == "secret" {
			return Deny
		}
		return Keep
	}
	val := map[string]any{
		"leak":      "https://github.com/victim/secret/pull/42", // aliased url → denied repo
		"leak2":     "/victim/secret/issues/7",                  // aliased resourcePath → denied repo
		"url":       "https://github.com/me/allowed/pull/1",     // canonical, allowed repo → kept
		"createdAt": "2026-01-01T00:00:00Z",                     // non-repo string → kept
	}
	scrubCrossRepoURIScalars(val, deny, "CrossReferencedEvent")
	if val["leak"] != nil {
		t.Errorf("aliased denied-repo url not nulled (alias dodge): %v", val["leak"])
	}
	if val["leak2"] != nil {
		t.Errorf("aliased denied-repo resourcePath not nulled: %v", val["leak2"])
	}
	if val["url"] == nil {
		t.Errorf("allowed canonical url wrongly nulled")
	}
	if val["createdAt"] == nil {
		t.Errorf("non-repo string wrongly nulled (value-driven scan over-redacted)")
	}
}
