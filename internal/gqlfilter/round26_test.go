package gqlfilter

import (
	"encoding/json"
	"strings"
	"testing"
)

// denied callback for the tests: acme = base read + members none; ent-none / noorg = base denied; others allow.
func r26Denied(owner, resource string) bool {
	switch owner {
	case "acme":
		return resource == "members"
	case "noorg", "ent-none":
		return true
	default:
		return false
	}
}

func r26Redact(t *testing.T, body string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	return RedactDeniedOwnerPrivate(m, r26Denied).(map[string]any)
}

// TestR26_AliasedMemberFieldRedacted pins the round-26 HIGH-2 fix: a members-denied org's member field is
// nulled by its RESPONSE KEY (the per-field marker), so a client ALIAS can't dodge it; non-member base
// metadata of a base-allowed org survives.
func TestR26_AliasedMemberFieldRedacted(t *testing.T) {
	out := r26Redact(t, `{"bghOrgLoginZ9":"acme","bghOrgMemZ9_roster":"Organization",`+
		`"roster":{"nodes":[{"login":"secret-admin"}]},"description":"public-desc"}`)
	s := mustJSON(out)
	if strings.Contains(s, "secret-admin") {
		t.Fatalf("aliased member field leaked: %s", s)
	}
	if !strings.Contains(s, "public-desc") {
		t.Fatalf("base metadata of a members-only-denied org wrongly redacted: %s", s)
	}
	if strings.Contains(s, "bghOrg") {
		t.Fatalf("markers leaked into response: %s", s)
	}
}

// TestR26_BaseDeniedOwnerCoarseRedact pins HIGH-3/H-4: an owner the client has NO access to (base denied,
// e.g. repository().owner with a repo-only grant) is reduced to public identity — billing/IP-allow-list/
// domains/etc. are nulled even though they are not in any member-field list (drift-proof).
func TestR26_BaseDeniedOwnerCoarseRedact(t *testing.T) {
	out := r26Redact(t, `{"bghOrgLoginZ9":"noorg","login":"noorg","name":"No Org",`+
		`"organizationBillingEmail":"bill@secret","ipAllowListEntries":{"nodes":[{"allowListValue":"10.0.0.0/8"}]},`+
		`"domains":{"nodes":[{"domain":"secret.corp"}]}}`)
	s := mustJSON(out)
	for _, leak := range []string{"bill@secret", "10.0.0.0/8", "secret.corp"} {
		if strings.Contains(s, leak) {
			t.Fatalf("base-denied owner leaked %q: %s", leak, s)
		}
	}
	if !strings.Contains(s, "noorg") {
		t.Fatalf("public identity (login) wrongly redacted: %s", s)
	}
}

// TestR26_EnterprisePerResourceAndBase pins HIGH-1: an Enterprise base=read+members=none nulls its members
// but keeps billingEmail; a base=none enterprise is reduced to its slug.
func TestR26_EnterprisePerResourceAndBase(t *testing.T) {
	// base=none enterprise → everything but slug nulled
	out := r26Redact(t, `{"bghOrgLoginZ9":"ent-none","slug":"ent-none","billingEmail":"ent-bill",`+
		`"bghOrgMemZ9_members":"Enterprise","members":{"nodes":[{"login":"ent-member"}]}}`)
	s := mustJSON(out)
	if strings.Contains(s, "ent-bill") || strings.Contains(s, "ent-member") {
		t.Fatalf("base-denied enterprise leaked admin/member data: %s", s)
	}
	if !strings.Contains(s, "ent-none") {
		t.Fatalf("enterprise slug wrongly redacted: %s", s)
	}
}

// TestR26_AugmentMarksOrgAndEnterprise verifies the augmenter injects the owner marker + per-member-field
// markers (under the client's alias) for both Organization and Enterprise, including nested navigation.
func TestR26_AugmentMarksOrgAndEnterprise(t *testing.T) {
	s, _ := Load()
	out, err := s.Augment(`{ organization(login:"a"){ teams(first:1){ nodes{ organization{ roster: membersWithRole(first:1){ nodes{ login } } } } } }
		enterprise(slug:"e"){ members(first:1){ nodes{ __typename } } } }`)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"bghOrgLoginZ9: login", "bghOrgLoginZ9: slug", "bghOrgMemZ9_roster", "bghOrgMemZ9_members"} {
		if !strings.Contains(out, want) {
			t.Errorf("augmented query missing %q:\n%s", want, out)
		}
	}
}
