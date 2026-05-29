package policy

import (
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
	r := testPolicy().Evaluate("unknown/repo", "", classifier.Read)
	if r.Allowed {
		t.Fatal("should be denied")
	}
}

func TestOrgDefaultAllowsRead(t *testing.T) {
	r := testPolicy().Evaluate("my-company/unknown", "my-company", classifier.Read)
	if !r.Allowed {
		t.Fatalf("should be allowed: %s", r.Reason)
	}
}

func TestOrgDefaultDeniesWrite(t *testing.T) {
	r := testPolicy().Evaluate("my-company/unknown", "my-company", classifier.Write)
	if r.Allowed {
		t.Fatal("should be denied")
	}
}

func TestRepoOverrideAllowsWrite(t *testing.T) {
	r := testPolicy().Evaluate("my-company/frontend", "my-company", classifier.Write)
	if !r.Allowed {
		t.Fatalf("should be allowed: %s", r.Reason)
	}
}

func TestRepoOverrideNoneBlocksAll(t *testing.T) {
	r := testPolicy().Evaluate("my-company/deploy-infra", "my-company", classifier.Read)
	if r.Allowed {
		t.Fatal("should be denied")
	}
}

func TestReadOnReadWriteAllowed(t *testing.T) {
	r := testPolicy().Evaluate("my-company/frontend", "my-company", classifier.Read)
	if !r.Allowed {
		t.Fatalf("should be allowed: %s", r.Reason)
	}
}

func TestAllowDefaultPermitsUnknown(t *testing.T) {
	p := &Policy{Defaults: Defaults{Mode: ModeAllow}}
	r := p.Evaluate("any/repo", "", classifier.Write)
	if !r.Allowed {
		t.Fatal("should be allowed")
	}
}

func TestNoRepoNoOrgUsesDefault(t *testing.T) {
	r := testPolicy().Evaluate("", "", classifier.Read)
	if r.Allowed {
		t.Fatal("should be denied")
	}
}

func TestOrgOnlyNoRepo(t *testing.T) {
	r := testPolicy().Evaluate("", "my-company", classifier.Read)
	if !r.Allowed {
		t.Fatalf("should be allowed: %s", r.Reason)
	}
}
