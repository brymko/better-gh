package gqlfilter

import "testing"

func TestLoadSchemaAndRepoScopedTypes(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// Repository itself and the common repo-scoped object types must be detected.
	mustScoped := []string{"Repository", "Issue", "PullRequest", "IssueComment",
		"PullRequestReview", "CommitComment", "Release", "Ref", "Label", "Milestone",
		"Commit", "Discussion"}
	for _, ty := range mustScoped {
		if !s.isRepoScoped(ty) {
			t.Errorf("%s should be repo-scoped", ty)
		}
	}
	// Non-repo types must NOT be flagged (else we'd redact legitimate data).
	for _, ty := range []string{"User", "Organization", "Query", "RateLimit", "Gist"} {
		if s.isRepoScoped(ty) {
			t.Errorf("%s should NOT be repo-scoped", ty)
		}
	}
	if n := len(s.repoScoped); n < 50 {
		t.Fatalf("expected many repo-scoped types, got %d", n)
	}
	t.Logf("repo-scoped types: %d", len(s.repoScoped))
}
