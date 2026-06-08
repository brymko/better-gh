package gqlfilter

import (
	"strings"
	"testing"
)

// Round-20: the @docsCategory-derived per-resource map must gate DeployKey on "keys" (not the
// "metadata" default that bypassed a keys="none" carve-out) and RefUpdateRule on "branches".
func TestR20_FilterResourcePins(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for typ, want := range map[string]string{
		"DeployKey":     "keys",
		"RefUpdateRule": "branches",
		"Ref":           "branches",
		"Submodule":     "contents",
	} {
		if got := s.FilterResource(typ); got != want {
			t.Errorf("FilterResource(%q) = %q, want %q", typ, got, want)
		}
	}
}

// Round-20: org/user/enterprise-owned Node types must be in the owner-owned set (node(id:) reads fail
// closed), while repo-scoped and genuinely-public Node types must not be.
func TestR20_OwnerOwnedNodeSet(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"Organization", "Team", "ProjectV2", "User"} {
		if !s.IsOwnerOwnedNodeType(typ) {
			t.Errorf("IsOwnerOwnedNodeType(%q) = false, want true (owner-private node)", typ)
		}
	}
	// Repository is repo-attributable (resolved to its own repo); a license is public — neither fails closed.
	for _, typ := range []string{"Repository", "License", "CodeOfConduct"} {
		if s.IsOwnerOwnedNodeType(typ) {
			t.Errorf("IsOwnerOwnedNodeType(%q) = true, want false (repo-attributable or public)", typ)
		}
	}
}

// Round-20: the repo-identity-scalar derivation must record nameWithOwner (fully attributable) vs a
// bare repositoryName (fail-closed under a non-repo scope).
func TestR20_RepoIdentityScalarDerivation(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := s.repoIdentityScalar["EnterpriseRepositoryInfo"]; got != "nameWithOwner" {
		t.Errorf("repoIdentityScalar[EnterpriseRepositoryInfo] = %q, want nameWithOwner", got)
	}
	if got := s.repoIdentityScalar["RepositoryMigration"]; got != "repositoryName" {
		t.Errorf("repoIdentityScalar[RepositoryMigration] = %q, want repositoryName", got)
	}
}

// Round-20: the response filter must redact repoIdentityNoPath objects reached by navigation — an
// EnterpriseRepositoryInfo (self-identifying owner/repo) against its real repo, and a RepositoryMigration
// (bare name) fail-closed under a non-repo (org) scope where there is no ambient repository.
func TestR20_RepoIdentityNoPathRedaction(t *testing.T) {
	// EnterpriseRepositoryInfo carries the repo marker augment injects from nameWithOwner.
	resp := map[string]any{
		"enterprise": map[string]any{
			"repos": []any{
				map[string]any{markerAlias: "victim/secret", markerTypeAlias: "EnterpriseRepositoryInfo", "isPrivate": true, "nameWithOwner": "victim/secret"},
			},
		},
		// RepositoryMigration carries only a type marker (bare repositoryName) under an org — no ambient repo.
		"organization": map[string]any{
			"repositoryMigrations": map[string]any{
				"nodes": []any{
					map[string]any{markerTypeAlias: "RepositoryMigration", "repositoryName": "topsecret", "migrationLogUrl": "https://x"},
				},
			},
		},
	}
	out := FilterWithDecision(resp, func(owner, repo, resource, typename string) Decision {
		if owner == "victim" {
			return Deny
		}
		return Keep
	})
	s := mustJSON(out)
	if strings.Contains(s, "victim/secret") || strings.Contains(s, "topsecret") || strings.Contains(s, "migrationLogUrl") {
		t.Fatalf("repoIdentityNoPath objects leaked through the filter: %s", s)
	}
	// markers themselves must never reach the client.
	if strings.Contains(s, markerAlias) || strings.Contains(s, markerTypeAlias) {
		t.Fatalf("injected markers leaked to client: %s", s)
	}
}

// Round-20: the known-type helper recognizes embedded-schema object types and rejects unknown ones, so
// the proxy callback can fail closed on a repo-marked object whose runtime __typename is unknown.
func TestR20_IsKnownObjectType(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !s.IsKnownObjectType("Repository") || !s.IsKnownObjectType("Submodule") {
		t.Errorf("known object types reported unknown")
	}
	if s.IsKnownObjectType("DefinitelyNotARealType_R20") {
		t.Errorf("unknown type reported known")
	}
}
