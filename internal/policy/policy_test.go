package policy

import (
	"os"
	"path/filepath"
	"testing"

	"better-gh/internal/classifier"
)

func testPolicy() *Policy {
	return &Policy{
		Defaults: Defaults{Mode: ModeDeny},
		Org: []OrgRule{
			{Name: "my-company", Access: AccessRead},
		},
		Repo: []RepoRule{
			{Name: "my-company/frontend", Access: AccessReadWrite},
			{Name: "my-company/deploy-infra", Access: AccessNone},
		},
	}
}

func TestDenyDefaultBlocksUnknown(t *testing.T) {
	r := testPolicy().Evaluate("unknown/repo", "", classifier.Read, "", "")
	if r.Allowed {
		t.Fatal("should be denied")
	}
}

func TestOrgDefaultAllowsRead(t *testing.T) {
	r := testPolicy().Evaluate("my-company/unknown", "my-company", classifier.Read, "", "")
	if !r.Allowed {
		t.Fatalf("should be allowed: %s", r.Reason)
	}
}

func TestOrgDefaultDeniesWrite(t *testing.T) {
	r := testPolicy().Evaluate("my-company/unknown", "my-company", classifier.Write, "", "")
	if r.Allowed {
		t.Fatal("should be denied")
	}
}

func TestRepoOverrideAllowsWrite(t *testing.T) {
	r := testPolicy().Evaluate("my-company/frontend", "my-company", classifier.Write, "", "")
	if !r.Allowed {
		t.Fatalf("should be allowed: %s", r.Reason)
	}
}

func TestRepoOverrideNoneBlocksAll(t *testing.T) {
	r := testPolicy().Evaluate("my-company/deploy-infra", "my-company", classifier.Read, "", "")
	if r.Allowed {
		t.Fatal("should be denied")
	}
}

func TestReadOnReadWriteAllowed(t *testing.T) {
	r := testPolicy().Evaluate("my-company/frontend", "my-company", classifier.Read, "", "")
	if !r.Allowed {
		t.Fatalf("should be allowed: %s", r.Reason)
	}
}

func TestAllowDefaultPermitsUnknown(t *testing.T) {
	p := &Policy{Defaults: Defaults{Mode: ModeAllow}}
	r := p.Evaluate("any/repo", "", classifier.Write, "", "")
	if !r.Allowed {
		t.Fatal("should be allowed")
	}
}

func TestNoRepoNoOrgUsesDefault(t *testing.T) {
	r := testPolicy().Evaluate("", "", classifier.Read, "", "")
	if r.Allowed {
		t.Fatal("should be denied")
	}
}

func TestOrgOnlyNoRepo(t *testing.T) {
	r := testPolicy().Evaluate("", "my-company", classifier.Read, "", "")
	if !r.Allowed {
		t.Fatalf("should be allowed: %s", r.Reason)
	}
}

func TestRepoPermissionsOverrideAccess(t *testing.T) {
	p := &Policy{
		Defaults: Defaults{Mode: ModeDeny},
		Repo: []RepoRule{
			{
				Name:   "org/repo",
				Access: AccessRead,
				Permissions: map[string]Access{
					"pulls": AccessReadWrite,
				},
			},
		},
	}
	r := p.Evaluate("org/repo", "org", classifier.Write, "pulls", "")
	if !r.Allowed {
		t.Fatalf("pulls should allow write: %s", r.Reason)
	}

	r = p.Evaluate("org/repo", "org", classifier.Write, "issues", "")
	if r.Allowed {
		t.Fatal("issues should fall back to repo access=read, deny write")
	}
}

func TestRepoPermissionsNoneBlocksResource(t *testing.T) {
	p := &Policy{
		Defaults: Defaults{Mode: ModeDeny},
		Repo: []RepoRule{
			{
				Name:   "org/repo",
				Access: AccessReadWrite,
				Permissions: map[string]Access{
					"actions": AccessNone,
				},
			},
		},
	}
	r := p.Evaluate("org/repo", "org", classifier.Read, "actions", "")
	if r.Allowed {
		t.Fatal("actions=none should block reads")
	}

	r = p.Evaluate("org/repo", "org", classifier.Write, "pulls", "")
	if !r.Allowed {
		t.Fatalf("pulls should fall back to repo access=read-write: %s", r.Reason)
	}
}

func TestOrgPermissionsOverrideAccess(t *testing.T) {
	p := &Policy{
		Defaults: Defaults{Mode: ModeDeny},
		Org: []OrgRule{
			{
				Name:   "org",
				Access: AccessRead,
				Permissions: map[string]Access{
					"pulls": AccessReadWrite,
				},
			},
		},
	}
	r := p.Evaluate("org/unknown-repo", "org", classifier.Write, "pulls", "")
	if !r.Allowed {
		t.Fatalf("org pulls should allow write: %s", r.Reason)
	}

	r = p.Evaluate("org/unknown-repo", "org", classifier.Write, "issues", "")
	if r.Allowed {
		t.Fatal("org issues should fall back to org access=read, deny write")
	}
}

func TestUnscopedCategoryAllowsRead(t *testing.T) {
	p := &Policy{
		Defaults: Defaults{
			Mode: ModeDeny,
			Unscoped: map[string]Access{
				"user":   AccessRead,
				"search": AccessRead,
			},
		},
	}
	r := p.Evaluate("", "", classifier.Read, "", "user")
	if !r.Allowed {
		t.Fatalf("user read should be allowed: %s", r.Reason)
	}

	r = p.Evaluate("", "", classifier.Write, "", "user")
	if r.Allowed {
		t.Fatal("user write should be denied")
	}

	r = p.Evaluate("", "", classifier.Read, "", "gists")
	if r.Allowed {
		t.Fatal("gists not in unscoped map, should be denied by default")
	}
}

func TestUnscopedCategoryReadWrite(t *testing.T) {
	p := &Policy{
		Defaults: Defaults{
			Mode: ModeDeny,
			Unscoped: map[string]Access{
				"gists": AccessReadWrite,
			},
		},
	}
	r := p.Evaluate("", "", classifier.Write, "", "gists")
	if !r.Allowed {
		t.Fatalf("gists write should be allowed: %s", r.Reason)
	}
}

func TestEmptyResourceFallsBackToRuleAccess(t *testing.T) {
	p := &Policy{
		Defaults: Defaults{Mode: ModeDeny},
		Repo: []RepoRule{
			{
				Name:   "org/repo",
				Access: AccessRead,
				Permissions: map[string]Access{
					"pulls": AccessReadWrite,
				},
			},
		},
	}
	r := p.Evaluate("org/repo", "org", classifier.Read, "", "")
	if !r.Allowed {
		t.Fatalf("empty resource should use repo access: %s", r.Reason)
	}
}

func TestRepoPermTakesPriorityOverOrg(t *testing.T) {
	p := &Policy{
		Defaults: Defaults{Mode: ModeDeny},
		Org: []OrgRule{
			{
				Name:   "org",
				Access: AccessReadWrite,
			},
		},
		Repo: []RepoRule{
			{
				Name:   "org/repo",
				Access: AccessRead,
				Permissions: map[string]Access{
					"pulls": AccessNone,
				},
			},
		},
	}
	r := p.Evaluate("org/repo", "org", classifier.Read, "pulls", "")
	if r.Allowed {
		t.Fatal("repo-level pulls=none should take priority over org read-write")
	}
}

func TestUnscopedNoneBlocks(t *testing.T) {
	p := &Policy{
		Defaults: Defaults{
			Mode: ModeAllow,
			Unscoped: map[string]Access{
				"gists": AccessNone,
			},
		},
	}
	r := p.Evaluate("", "", classifier.Read, "", "gists")
	if r.Allowed {
		t.Fatal("gists=none should block even with mode=allow")
	}
}

func TestUnscopedWithModeAllow(t *testing.T) {
	p := &Policy{
		Defaults: Defaults{
			Mode: ModeAllow,
			Unscoped: map[string]Access{
				"user": AccessRead,
			},
		},
	}
	r := p.Evaluate("", "", classifier.Write, "", "user")
	if r.Allowed {
		t.Fatal("user=read should deny writes even with mode=allow")
	}

	r = p.Evaluate("", "", classifier.Read, "", "user")
	if !r.Allowed {
		t.Fatalf("user=read should allow reads: %s", r.Reason)
	}

	r = p.Evaluate("", "", classifier.Read, "", "notifications")
	if !r.Allowed {
		t.Fatalf("unlisted category with mode=allow should be allowed: %s", r.Reason)
	}
}

func TestOrgPermissionsNoneBlocks(t *testing.T) {
	p := &Policy{
		Defaults: Defaults{Mode: ModeDeny},
		Org: []OrgRule{
			{
				Name:   "org",
				Access: AccessReadWrite,
				Permissions: map[string]Access{
					"hooks": AccessNone,
				},
			},
		},
	}
	r := p.Evaluate("org/repo", "org", classifier.Read, "hooks", "")
	if r.Allowed {
		t.Fatal("org hooks=none should block reads")
	}
	r = p.Evaluate("org/repo", "org", classifier.Read, "pulls", "")
	if !r.Allowed {
		t.Fatalf("org pulls should fall back to org access=read-write: %s", r.Reason)
	}
}

func TestTOMLLoadPermissionsAndUnscoped(t *testing.T) {
	tomlContent := `
[defaults]
mode = "deny"

[defaults.unscoped]
user = "read"
search = "read"
gists = "read-write"

[[org]]
name = "my-org"
access = "read"

[org.permissions]
pulls = "read-write"

[[repo]]
name = "my-org/frontend"
access = "read"

[repo.permissions]
pulls = "read-write"
actions = "none"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	if err := os.WriteFile(path, []byte(tomlContent), 0o644); err != nil {
		t.Fatal(err)
	}

	p, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}

	if p.Defaults.Mode != ModeDeny {
		t.Fatal("expected deny")
	}
	if len(p.Defaults.Unscoped) != 3 {
		t.Fatalf("expected 3 unscoped entries, got %d", len(p.Defaults.Unscoped))
	}
	if p.Defaults.Unscoped["user"] != AccessRead {
		t.Fatal("expected user=read")
	}
	if p.Defaults.Unscoped["gists"] != AccessReadWrite {
		t.Fatal("expected gists=read-write")
	}

	if len(p.Org) != 1 || p.Org[0].Permissions["pulls"] != AccessReadWrite {
		t.Fatal("expected org pulls=read-write")
	}

	if len(p.Repo) != 1 {
		t.Fatalf("expected 1 repo rule, got %d", len(p.Repo))
	}
	if p.Repo[0].Permissions["pulls"] != AccessReadWrite {
		t.Fatal("expected repo pulls=read-write")
	}
	if p.Repo[0].Permissions["actions"] != AccessNone {
		t.Fatal("expected repo actions=none")
	}

	r := p.Evaluate("my-org/frontend", "my-org", classifier.Write, "pulls", "")
	if !r.Allowed {
		t.Fatalf("frontend pulls write should be allowed: %s", r.Reason)
	}

	r = p.Evaluate("my-org/frontend", "my-org", classifier.Read, "actions", "")
	if r.Allowed {
		t.Fatal("frontend actions read should be denied")
	}

	r = p.Evaluate("", "", classifier.Read, "", "user")
	if !r.Allowed {
		t.Fatalf("unscoped user read should be allowed: %s", r.Reason)
	}

	r = p.Evaluate("", "", classifier.Write, "", "gists")
	if !r.Allowed {
		t.Fatalf("unscoped gists write should be allowed: %s", r.Reason)
	}
}
