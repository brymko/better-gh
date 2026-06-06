package policy

import "testing"

// TestR45_AnyRepoDeniesWriteUnderOrg pins round-45 F5: the proxy uses this to fail closed a numeric-repo-id
// write (selected_repository_ids[]) only when the policy actually denies SOME repo's write under the org —
// a token with no carve-out is unaffected, a base-none or per-resource-none carve-out is detected.
func TestR45_AnyRepoDeniesWriteUnderOrg(t *testing.T) {
	// org acme=rw, acme/secret base=rw but actions=none → a write to "actions" under acme could hit it.
	p := &Policy{
		Org:  []OrgRule{{Name: "acme", Access: AccessReadWrite}},
		Repo: []RepoRule{{Name: "acme/secret", Access: AccessReadWrite, Permissions: map[string]Access{"actions": AccessNone}}},
	}
	if !p.AnyRepoDeniesWriteUnderOrg("acme", "actions") {
		t.Error("a per-resource actions=none carve-out under acme must be detected")
	}
	// a DIFFERENT resource the carve-out does not deny → not flagged (the write is genuinely allowed).
	if p.AnyRepoDeniesWriteUnderOrg("acme", "secrets") {
		t.Error("a carve-out on actions must NOT flag a write to the unrelated secrets resource")
	}
	// base-none carve-out denies every resource's write.
	pBase := &Policy{
		Org:  []OrgRule{{Name: "acme", Access: AccessReadWrite}},
		Repo: []RepoRule{{Name: "acme/secret", Access: AccessNone}},
	}
	if !pBase.AnyRepoDeniesWriteUnderOrg("acme", "secrets") {
		t.Error("a base=none repo carve-out must be detected for any resource")
	}
	// no repo carve-out under acme → not flagged (every repo writable; any id is safe).
	pClean := &Policy{Org: []OrgRule{{Name: "acme", Access: AccessReadWrite}}}
	if pClean.AnyRepoDeniesWriteUnderOrg("acme", "actions") {
		t.Error("a policy with no repo carve-out under acme must NOT be flagged (no over-restriction)")
	}
	// a carve-out under a DIFFERENT org must not flag acme.
	pOther := &Policy{Repo: []RepoRule{{Name: "other/secret", Access: AccessNone}}}
	if pOther.AnyRepoDeniesWriteUnderOrg("acme", "actions") {
		t.Error("a carve-out under a different org must not flag acme")
	}
}
