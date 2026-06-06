package gqlfilter

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vektah/gqlparser/v2/ast"
)

// noUserFieldDenied is the shared owner-private-test userFieldDenied predicate that allows all user-private
// CATEGORIES (user_private/gists), so a test's redaction is driven only by its org-login `denied` callback
// (the round-26/27/28/29 semantics); the round-35 category gate is exercised separately in round35_test.go.
func noUserFieldDenied(string) bool { return false }

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
	return RedactDeniedOwnerPrivate(m, r26Denied, noUserFieldDenied).(map[string]any)
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

// TestR26_TeamMembersAttributedToOrg pins the structural fix: Team.members (the org's roster reached via
// organization(){teams{nodes{members}}}) is attributed to its ambient owner org and nulled under that org's
// members="none" — a non-owner type carrying owner-private member data.
func TestR26_TeamMembersAttributedToOrg(t *testing.T) {
	out := r26Redact(t, `{"bghOrgLoginZ9":"acme","teams":{"nodes":[{"bghOrgMemZ9_members":"Team",`+
		`"members":{"nodes":[{"login":"team-secret"}]}}]}}`)
	if s := mustJSON(out); strings.Contains(s, "team-secret") {
		t.Fatalf("Team.members not attributed to its org / not redacted under members=none: %s", s)
	}
	// fail-closed: a member-bearing object with NO attributable owner ancestor must still be nulled.
	out2 := r26Redact(t, `{"teams":{"nodes":[{"bghOrgMemZ9_members":"Team","members":{"nodes":[{"login":"orphan"}]}}]}}`)
	if s := mustJSON(out2); strings.Contains(s, "orphan") {
		t.Fatalf("member-bearing object with no owner ancestor must fail closed: %s", s)
	}
}

// TestOwnerPrivateCoverage is the structural coverage invariant (the owner-private analogue of the
// repo-coverage invariants that converged repo isolation). For every type in the org/enterprise hierarchy
// it DERIVES the member-identity fields from the schema — fields returning a connection whose element
// exposes a `login` (a roster of members/orgs) — rather than a hand-list (which in round-26 missed
// EnterpriseTeam.enterpriseTeamMembers), and asserts each is in that type's MARKED set so augment tags it
// and RedactDeniedOwnerPrivate nulls it under members="none". A schema refresh that adds a new
// member-roster field to one of these types fails the build instead of silently leaking by navigation.
func TestOwnerPrivateCoverage(t *testing.T) {
	s, _ := Load()
	unwrap := func(tp *ast.Type) string {
		for tp.Elem != nil {
			tp = tp.Elem
		}
		return tp.Name()
	}
	exposesLogin := func(typeName string) bool {
		for _, cand := range append([]*ast.Definition{s.schema.Types[typeName]}, s.schema.PossibleTypes[typeName]...) {
			if cand == nil {
				continue
			}
			for _, f := range cand.Fields {
				if f.Name == "login" {
					return true
				}
			}
		}
		return false
	}
	// an owner element (Organization/Enterprise) is itself owner-marked and redacted per its own policy,
	// so a field returning a connection/navigation of OWNERS is not a member ROSTER — exclude it.
	isOwner := func(name string) bool { return name == "Organization" || name == "Enterprise" }
	// a field is a member-roster field if its return element (one hop into a connection's nodes) exposes a
	// login AND is NOT itself an owner type — i.e. a roster of member USERS/mannequins, not an org-nav list.
	rosterField := func(f *ast.FieldDefinition) bool {
		rt := unwrap(f.Type)
		def := s.schema.Types[rt]
		if def == nil {
			return false
		}
		if exposesLogin(rt) && !isOwner(rt) {
			return true
		}
		for _, sub := range def.Fields {
			if sub.Name == "nodes" {
				if el := unwrap(sub.Type); exposesLogin(el) && !isOwner(el) {
					return true
				}
			}
		}
		return false
	}
	// sponsors/sponsoring expose login-bearing Sponsor connections but are PUBLIC GitHub Sponsors data
	// (round-22), not the private member roster — base-governed, not "members".
	publicRosterFields := map[string]bool{"sponsors": true, "sponsoring": true}
	ownerHierarchy := []string{"Organization", "Enterprise", "Team", "EnterpriseTeam", "EnterpriseOwnerInfo"}
	exceptions := map[string]string{
		"EnterpriseOwnerInfo": "reached only via Enterprise.ownerInfo, a marked Enterprise member field nulled with the enterprise",
	}
	markedSetOf := func(typ string) map[string]bool {
		switch typ {
		case "Organization":
			return orgMemberFieldNames
		case "Enterprise":
			return enterpriseMemberFieldNames
		default:
			return memberBearingNonOwnerTypes[typ]
		}
	}
	for _, name := range ownerHierarchy {
		def := s.schema.Types[name]
		if def == nil {
			continue
		}
		var declared []string
		for _, f := range def.Fields {
			if !publicRosterFields[f.Name] && rosterField(f) {
				declared = append(declared, f.Name)
			}
		}
		if len(declared) == 0 || exceptions[name] != "" {
			continue
		}
		marked := markedSetOf(name)
		if marked == nil {
			t.Errorf("owner-hierarchy type %q exposes member-roster fields %v but is NOT covered (not owner-marked, "+
				"not in memberBearingNonOwnerTypes, not an exception) — navigation leaks members=\"none\" data", name, declared)
			continue
		}
		for _, f := range declared {
			if !marked[f] {
				t.Errorf("owner-hierarchy type %q exposes member-roster field %q its marked set omits — augment "+
					"won't tag it, so it leaks under members=\"none\"", name, f)
			}
		}
	}
}
