package gqlfilter

import "testing"

// Round-21: the bare-repositoryName repo-identity type (RepositoryMigration) must be recognized so the
// response filter redacts it unconditionally (ambient attribution to a marked ancestor is unsound),
// while a nameWithOwner repo-identity type (self-attributable) is not flagged.
func TestR21_IsBareNameRepoIdentityType(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !s.IsBareNameRepoIdentityType("RepositoryMigration") {
		t.Errorf("RepositoryMigration must be a bare-name repo-identity type (unconditional redact)")
	}
	for _, typ := range []string{"EnterpriseRepositoryInfo", "UserNamespaceRepository", "Repository", "Issue"} {
		if s.IsBareNameRepoIdentityType(typ) {
			t.Errorf("%s must NOT be flagged bare-name (it self-attributes or is unrelated)", typ)
		}
	}
}

// Round-21: Gist/GistComment (owner-private secret gists) must be in the owner-owned node set so
// node(id:Gist) fails closed.
func TestR21_GistOwnerOwnedNode(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"Gist", "GistComment"} {
		if !s.IsOwnerOwnedNodeType(typ) {
			t.Errorf("IsOwnerOwnedNodeType(%q) = false, want true (owner-private gist)", typ)
		}
	}
}
