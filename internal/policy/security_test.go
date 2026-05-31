package policy

// Regression for FINDING 3 (HIGH): case-sensitivity policy bypass — now FIXED.
//
// Evaluate() previously compared repo/org names with exact string equality, while
// GitHub resolves owner/repo/org names case-insensitively. A re-cased path could
// dodge a restrictive [[repo]]/[[org]] rule and fall through to a permissive
// default. Evaluate() now uses strings.EqualFold; these tests assert the bypass is
// closed.

import (
	"testing"

	"better-gh/internal/classifier"
)

func TestSec_CaseInsensitiveRepoOverrideBypass(t *testing.T) {
	// Intent: read the whole org, but explicitly block one sensitive repo.
	pol := &Policy{
		Defaults: Defaults{Mode: ModeDeny},
		Org:      []OrgRule{{Name: "acme", Access: AccessRead}},
		Repo:     []RepoRule{{Name: "acme/secret", Access: AccessNone}},
	}

	for _, repo := range []string{"acme/secret", "acme/Secret", "acme/SECRET", "ACME/secret"} {
		// owner stays case-equivalent to "acme" so the org rule still matches; the
		// repo none-rule must catch every casing of the repo.
		res := pol.Evaluate(repo, "acme", classifier.Read, "metadata", "")
		if res.Allowed {
			t.Fatalf("FIXED-regressed: re-cased repo %q bypassed the 'none' rule", repo)
		}
	}
}

// Same defect on the org axis with default=allow: an org set to 'none' must stay
// blocked regardless of the org/owner segment's casing.
func TestSec_CaseInsensitiveOrgBypassUnderDefaultAllow(t *testing.T) {
	pol := &Policy{
		Defaults: Defaults{Mode: ModeAllow},
		Org:      []OrgRule{{Name: "blocked", Access: AccessNone}},
	}

	for _, org := range []string{"blocked", "Blocked", "BLOCKED"} {
		if pol.Evaluate("", org, classifier.Read, "", "").Allowed {
			t.Fatalf("FIXED-regressed: re-cased org %q bypassed the 'none' rule via default=allow", org)
		}
	}
}

// Regression for FINDING 5 (MEDIUM): when a rule carries per-resource permissions, a
// WRITE to an unrecognized resource (e.g. POST /repos/o/r/dispatches) fails closed
// instead of inheriting the base grant — so a per-resource 'none' can't be dodged via
// an unmapped sibling endpoint.
func TestSec_UnknownWriteFailsClosedWithPermissions(t *testing.T) {
	pol := &Policy{
		Defaults: Defaults{Mode: ModeDeny},
		Repo: []RepoRule{{
			Name:        "o/r",
			Access:      AccessReadWrite, // broad base grant ...
			Permissions: map[string]Access{"actions": AccessNone},
		}},
	}

	// Unknown write is denied despite the read-write base, because perms are in effect.
	if pol.Evaluate("o/r", "o", classifier.Write, classifier.ResourceUnknown, "").Allowed {
		t.Fatalf("FIXED-regressed: unknown write inherited base read-write past a per-resource policy")
	}
	// Unknown READ still uses the base grant (reads are not the escalation risk).
	if !pol.Evaluate("o/r", "o", classifier.Read, classifier.ResourceUnknown, "").Allowed {
		t.Fatalf("unknown read should still be allowed under base read-write")
	}
	// A recognized resource is unaffected (issues falls back to base read-write).
	if !pol.Evaluate("o/r", "o", classifier.Write, "issues", "").Allowed {
		t.Fatalf("known resource not in perms should use base access (read-write)")
	}
}

// Without per-resource permissions, behavior is unchanged: an unknown write uses the
// base grant (no granular intent to protect).
func TestSec_UnknownWriteUsesBaseWithoutPermissions(t *testing.T) {
	pol := &Policy{
		Defaults: Defaults{Mode: ModeDeny},
		Repo:     []RepoRule{{Name: "o/r", Access: AccessReadWrite}},
	}
	if !pol.Evaluate("o/r", "o", classifier.Write, classifier.ResourceUnknown, "").Allowed {
		t.Fatalf("unknown write should use base read-write when no per-resource perms are set")
	}
}
