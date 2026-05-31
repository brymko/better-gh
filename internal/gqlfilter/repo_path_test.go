package gqlfilter

import (
	"strings"
	"testing"
)

// Regression for FINDING I (HIGH): a type that links to its repository INDIRECTLY (e.g.
// DiscussionComment, whose only link is discussion → Discussion → repository — GitHub gives
// it no direct `repository` field, unlike IssueComment) was not derived as repo-scoped, so
// the augmenter injected no marker and the filter could not redact it. Reached cross-repo
// via viewer.repositoryDiscussionComments (no tagged ancestor), denied-repo comment bodies
// leaked. The derivation now follows one-hop membership and tags such selections.
func TestSec_IndirectRepoMembershipTagged(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	q := `query { viewer { repositoryDiscussionComments(first:50){ nodes { body } } } }`
	aug, err := s.Augment(q)
	if err != nil {
		t.Fatalf("augment: %v", err)
	}
	if !strings.Contains(aug, markerAlias) {
		t.Fatalf("no marker injected — DiscussionComment under viewer cannot be redacted:\n%s", aug)
	}
	// The marker must walk discussion → repository → nameWithOwner so the filter learns the
	// real repo of each comment.
	if !strings.Contains(aug, "discussion") || !strings.Contains(aug, "nameWithOwner") {
		t.Fatalf("marker does not follow the discussion→repository membership path:\n%s", aug)
	}
}

// Guards the repo-scoped derivation boundaries: content-bearing types that link to a repo
// (directly or via one hop) MUST be repo-scoped so the filter redacts them; the repo-less
// principals (User/Organization/Gist) MUST NOT be, or the augmenter would tag and redact
// every viewer/org/gist read and break it.
func TestSec_RepoScopedBoundaries(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	mustBeScoped := []string{
		"Repository", "Issue", "PullRequest", "IssueComment", "CommitComment",
		"PullRequestReview", "PullRequestReviewComment", "Commit", "Blob", "Ref",
		"Discussion", "DiscussionComment", "Release", "CheckRun", "CheckSuite",
	}
	for _, n := range mustBeScoped {
		if !s.IsRepoScopedType(n) {
			t.Errorf("%s must be repo-scoped (its data is repo-private)", n)
		}
	}
	mustNotBeScoped := []string{"User", "Organization", "Gist", "Query", "Mutation"}
	for _, n := range mustNotBeScoped {
		if s.IsRepoScopedType(n) {
			t.Errorf("%s must NOT be repo-scoped (it is not a single repo); tagging it would break reads of it", n)
		}
	}
}
