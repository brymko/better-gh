package proxy

import (
	"strings"
	"testing"
)

// TestR44_ErrorsScrubWebURL pins round-44 Finding 4: a github.com/owner/repo WEB url naming a denied repo in
// a GraphQL errors[]/extensions string is scrubbed — the owner/repo regex mis-tokenizes the URL as
// github.com/owner and orphans the real repo, so the scrub now parses URLs with the data-side RepoFromWebURL.
func TestR44_ErrorsScrubWebURL(t *testing.T) {
	denied := func(ownerRepo string) bool { return strings.EqualFold(ownerRepo, "secretcorp/private") }

	for _, msg := range []string{
		"This repository has moved. Please use https://github.com/secretcorp/private instead.",
		"see https://github.com/secretcorp/private/issues/3",
		"clone https://github.com/secretcorp/private.git",
	} {
		got, _ := scrubDeniedRepoStrings(msg, denied).(string)
		if strings.Contains(got, "secretcorp/private") {
			t.Fatalf("F4: github.com web-URL denied repo not scrubbed: %q", got)
		}
	}

	// a github.com URL for an ALLOWED repo, and a non-repo github.com/orgs URL, must NOT be scrubbed.
	keep, _ := scrubDeniedRepoStrings("see https://github.com/octocat/hello-world and https://github.com/orgs/acme", denied).(string)
	if !strings.Contains(keep, "octocat/hello-world") || !strings.Contains(keep, "orgs/acme") {
		t.Fatalf("F4: an allowed/non-repo github.com URL was wrongly scrubbed: %q", keep)
	}
}
