package policy

import (
	"os"
	"path/filepath"
	"strings"
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
		t.Fatal("should be allowed (repo is non-empty, not unscoped)")
	}
}

func TestAllowDefaultDeniesUnscopedWrite(t *testing.T) {
	p := &Policy{Defaults: Defaults{Mode: ModeAllow}}
	r := p.Evaluate("", "", classifier.Write, "", "")
	if r.Allowed {
		t.Fatal("unscoped write should be denied even with mode=allow")
	}
}

func TestAllowDefaultPermitsUnscopedRead(t *testing.T) {
	p := &Policy{Defaults: Defaults{Mode: ModeAllow}}
	r := p.Evaluate("", "", classifier.Read, "", "")
	if !r.Allowed {
		t.Fatal("unscoped read with mode=allow should be allowed")
	}
}

func TestReadDefaultPermitsUnknownRead(t *testing.T) {
	p := &Policy{Defaults: Defaults{Mode: ModeRead}}
	r := p.Evaluate("any/repo", "", classifier.Read, "", "")
	if !r.Allowed {
		t.Fatalf("read default should allow unmatched read: %s", r.Reason)
	}
}

func TestReadDefaultDeniesUnknownWrite(t *testing.T) {
	p := &Policy{Defaults: Defaults{Mode: ModeRead}}
	r := p.Evaluate("any/repo", "", classifier.Write, "", "")
	if r.Allowed {
		t.Fatal("read default should deny unmatched write")
	}
}

func TestReadDefaultPermitsUnscopedRead(t *testing.T) {
	p := &Policy{Defaults: Defaults{Mode: ModeRead}}
	r := p.Evaluate("", "", classifier.Read, "", "")
	if !r.Allowed {
		t.Fatalf("read default should allow unmatched unscoped read: %s", r.Reason)
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

// Round-12 audit H2: a WRITE whose resource is indeterminate ("") or unrecognized must NOT
// inherit base access when a per-resource rule is in effect — else an unmapped GraphQL mutation
// (addComment/addReaction/lockLockable → "") or REST endpoint dodges a per-resource 'none'.
func TestIndeterminateWriteFailsClosedUnderPerResourceRule(t *testing.T) {
	p := &Policy{
		Repo: []RepoRule{{
			Name:        "o/rw",
			Access:      AccessReadWrite,
			Permissions: map[string]Access{"pulls": AccessNone},
		}},
		Org: []OrgRule{{
			Name:        "o",
			Access:      AccessReadWrite,
			Permissions: map[string]Access{"issues": AccessNone},
		}},
	}
	// Writes with an indeterminate/unrecognized resource fail closed.
	for _, res := range []string{"", classifier.ResourceUnknown} {
		if r := p.Evaluate("o/rw", "o", classifier.Write, res, ""); r.Allowed {
			t.Errorf("repo write with resource=%q should be denied under a per-resource rule", res)
		}
		if r := p.Evaluate("", "o", classifier.Write, res, ""); r.Allowed {
			t.Errorf("org write with resource=%q should be denied under a per-resource rule", res)
		}
	}
	// Reads with an empty resource still fall back to base access (unchanged behavior).
	if r := p.Evaluate("o/rw", "o", classifier.Read, "", ""); !r.Allowed {
		t.Errorf("empty-resource READ should still fall back to base access: %s", r.Reason)
	}
	// A rule WITHOUT per-resource permissions is unaffected (the per-resource gate never engages).
	plain := &Policy{Repo: []RepoRule{{Name: "o/rw", Access: AccessReadWrite}}}
	if r := plain.Evaluate("o/rw", "o", classifier.Write, "", ""); !r.Allowed {
		t.Errorf("write with empty resource should be allowed when the rule has no per-resource permissions: %s", r.Reason)
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

func TestNilPermissionsMapBehavesLikeEmpty(t *testing.T) {
	p := &Policy{
		Defaults: Defaults{Mode: ModeDeny},
		Repo: []RepoRule{
			{Name: "org/repo", Access: AccessReadWrite, Permissions: nil},
		},
	}
	r := p.Evaluate("org/repo", "org", classifier.Write, "pulls", "")
	if !r.Allowed {
		t.Fatalf("nil permissions should fall through to access=read-write: %s", r.Reason)
	}
}

func TestEmptyPermissionsMapBehavesLikeNil(t *testing.T) {
	p := &Policy{
		Defaults: Defaults{Mode: ModeDeny},
		Repo: []RepoRule{
			{Name: "org/repo", Access: AccessReadWrite, Permissions: map[string]Access{}},
		},
	}
	r := p.Evaluate("org/repo", "org", classifier.Write, "pulls", "")
	if !r.Allowed {
		t.Fatalf("empty permissions should fall through to access=read-write: %s", r.Reason)
	}
}

func TestReasonStringContainsResourceName(t *testing.T) {
	p := &Policy{
		Defaults: Defaults{Mode: ModeDeny},
		Repo: []RepoRule{
			{
				Name:   "org/repo",
				Access: AccessRead,
				Permissions: map[string]Access{
					"actions": AccessNone,
				},
			},
		},
	}
	r := p.Evaluate("org/repo", "org", classifier.Read, "actions", "")
	if r.Allowed {
		t.Fatal("should be denied")
	}
	if !strings.Contains(r.Reason, "actions") {
		t.Fatalf("reason should mention resource name, got: %s", r.Reason)
	}
	if !strings.Contains(r.Reason, "none") {
		t.Fatalf("reason should mention access level, got: %s", r.Reason)
	}
}

func TestReasonStringForOrg(t *testing.T) {
	p := &Policy{
		Defaults: Defaults{Mode: ModeDeny},
		Org: []OrgRule{
			{
				Name:   "org",
				Access: AccessRead,
				Permissions: map[string]Access{
					"hooks": AccessNone,
				},
			},
		},
	}
	r := p.Evaluate("org/repo", "org", classifier.Read, "hooks", "")
	if r.Allowed {
		t.Fatal("should be denied")
	}
	if !strings.Contains(r.Reason, "hooks") {
		t.Fatalf("reason should mention resource, got: %s", r.Reason)
	}
}

func TestReasonStringForUnscopedCategory(t *testing.T) {
	p := &Policy{
		Defaults: Defaults{
			Mode: ModeDeny,
			Unscoped: map[string]Access{
				"gists": AccessRead,
			},
		},
	}
	r := p.Evaluate("", "", classifier.Write, "", "gists")
	if r.Allowed {
		t.Fatal("should be denied")
	}
	if !strings.Contains(r.Reason, "gists") {
		t.Fatalf("reason should mention category, got: %s", r.Reason)
	}
}

func TestMultipleRepoRulesSecondMatches(t *testing.T) {
	p := &Policy{
		Defaults: Defaults{Mode: ModeDeny},
		Repo: []RepoRule{
			{Name: "org/other", Access: AccessNone},
			{Name: "org/target", Access: AccessReadWrite},
		},
	}
	r := p.Evaluate("org/target", "org", classifier.Write, "", "")
	if !r.Allowed {
		t.Fatalf("second repo rule should match: %s", r.Reason)
	}
}

func TestUnscopedWithRepoScopedRequest(t *testing.T) {
	p := &Policy{
		Defaults: Defaults{
			Mode: ModeDeny,
			Unscoped: map[string]Access{
				"user": AccessReadWrite,
			},
		},
	}
	r := p.Evaluate("org/repo", "org", classifier.Read, "", "")
	if r.Allowed {
		t.Fatal("unscoped rules should not apply to repo-scoped requests")
	}
}

func TestNilUnscopedMapWithCategory(t *testing.T) {
	p := &Policy{
		Defaults: Defaults{Mode: ModeDeny, Unscoped: nil},
	}
	r := p.Evaluate("", "", classifier.Read, "", "user")
	if r.Allowed {
		t.Fatal("nil unscoped map should fall through to default deny")
	}
}

func TestAccessMarshalText(t *testing.T) {
	tests := []struct {
		access Access
		want   string
	}{
		{AccessNone, "none"},
		{AccessRead, "read"},
		{AccessReadWrite, "read-write"},
	}
	for _, tt := range tests {
		got, err := tt.access.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != tt.want {
			t.Errorf("MarshalText(%d) = %q, want %q", tt.access, got, tt.want)
		}
	}
}

func TestDefaultModeMarshalText(t *testing.T) {
	deny, _ := ModeDeny.MarshalText()
	if string(deny) != "deny" {
		t.Errorf("ModeDeny.MarshalText() = %q, want deny", deny)
	}
	allow, _ := ModeAllow.MarshalText()
	if string(allow) != "allow" {
		t.Errorf("ModeAllow.MarshalText() = %q, want allow", allow)
	}
}

func TestAccessUnmarshalTextAliases(t *testing.T) {
	tests := []struct {
		text string
		want Access
	}{
		{"none", AccessNone},
		{"read", AccessRead},
		{"read-write", AccessReadWrite},
		{"readwrite", AccessReadWrite},
		{"write", AccessReadWrite},
	}
	for _, tt := range tests {
		var a Access
		if err := a.UnmarshalText([]byte(tt.text)); err != nil {
			t.Fatalf("UnmarshalText(%q): %v", tt.text, err)
		}
		if a != tt.want {
			t.Errorf("UnmarshalText(%q) = %d, want %d", tt.text, a, tt.want)
		}
	}
}

func TestAccessUnmarshalTextInvalid(t *testing.T) {
	var a Access
	if err := a.UnmarshalText([]byte("invalid")); err == nil {
		t.Fatal("expected error for invalid access")
	}
}

func TestDefaultModeUnmarshalTextInvalid(t *testing.T) {
	var m DefaultMode
	if err := m.UnmarshalText([]byte("invalid")); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestLoadFromFileNotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/path/policy.toml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoadFromFileInvalidTOML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.toml")
	os.WriteFile(path, []byte("{{{{invalid toml"), 0o644)
	_, err := LoadFromFile(path)
	if err == nil {
		t.Fatal("expected error for invalid TOML")
	}
}

// --- Security audit tests ---

func TestSec_DefaultAllowPermitsUnscopedWrite(t *testing.T) {
	p := &Policy{
		Defaults: Defaults{Mode: ModeAllow},
		Repo: []RepoRule{
			{Name: "org/secret", Access: AccessNone},
		},
	}
	r := p.Evaluate("", "", classifier.Write, "pulls", "")
	if r.Allowed {
		t.Fatal("unscoped write should be denied regardless of default mode")
	}
}

func TestSec_WriteWithResourceButNoScopeFallsToDefault(t *testing.T) {
	// Even with a resource identified (e.g. "pulls"), if repo/org are empty,
	// the evaluation falls straight to defaults.mode.
	p := &Policy{
		Defaults: Defaults{Mode: ModeDeny},
		Repo: []RepoRule{
			{Name: "org/repo", Access: AccessReadWrite},
		},
	}
	r := p.Evaluate("", "", classifier.Write, "pulls", "")
	if r.Allowed {
		t.Fatal("unscoped write should be denied with default=deny")
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
