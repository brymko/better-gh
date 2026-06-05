package gqlfilter

import (
	"sort"
	"strings"
	"testing"
)

// TestQueryRootCoverage is the GraphQL analogue of restfilter's knownGetOps fail-closed guard: it
// enumerates EVERY field of the embedded schema's Query root and asserts each is accounted for — either
// the classifier emits a real scope for it (classifierScopedRoots) or it is a documented public / global /
// token-gated / filter-covered root (publicSafeRoots). A future schema snapshot that adds a new Query root
// returning OWNER-PRIVATE non-repo data (the enterprise/gist class — data the repo-centric response filter
// never redacts) lands in NEITHER set and fails this test, forcing a triage decision instead of silently
// leaking under Defaults.Mode=allow (round-21 enterprise; round-22 enterprise*Invitation).
//
// The two sets mirror internal/classifier collectGraphQLScopes; this duplication is the point — the guard
// exists to force a human to classify each new root, not to re-derive the classifier.
func TestQueryRootCoverage(t *testing.T) {
	sch, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if sch.schema.Query == nil {
		t.Fatal("schema has no Query root")
	}

	// Roots the classifier scopes (repo / org / owner / enterprise) or recurses through.
	classifierScopedRoots := map[string]bool{
		"repository": true, "repositoryOwner": true, "organization": true, "user": true,
		"search": true, "viewer": true, "rateLimit": true, "node": true, "nodes": true,
		"enterprise": true, "enterpriseAdministratorInvitation": true, "enterpriseMemberInvitation": true,
		"relay": true, // returns Query; collectGraphQLScopes recurses into its selection set
	}

	// Roots that cannot disclose owner-private data the client could not otherwise obtain — each with a
	// specific reason, so a genuinely new owner-private root is NOT silently covered.
	publicSafeRoots := map[string]string{
		"codeOfConduct":           "public code-of-conduct templates",
		"codesOfConduct":          "public code-of-conduct templates",
		"license":                 "public open-source license templates",
		"licenses":                "public open-source license templates",
		"marketplaceCategories":   "public GitHub Marketplace data",
		"marketplaceCategory":     "public GitHub Marketplace data",
		"marketplaceListing":      "public GitHub Marketplace data",
		"marketplaceListings":     "public GitHub Marketplace data",
		"meta":                    "public GitHub service metadata (IP ranges)",
		"securityAdvisories":      "public GHSA advisory database",
		"securityAdvisory":        "public GHSA advisory database",
		"securityVulnerabilities": "public vulnerability database",
		"sponsorables":            "public sponsorable-account directory",
		"topic":                   "public repository-topic metadata",
		"id":                      "the Query node's own opaque id (scalar, no data)",
		// resource(url:) resolves a URL to a node; a Repository/Issue/PR result carries a repo marker and is
		// redacted by the response filter, a User/Organization result is public profile data.
		"resource": "URL resolver; repo-scoped results carry markers and are filter-redacted, non-repo results are public",
		// *ByToken invitation roots require the secret invitation token — the token IS the authorization, so
		// reading one is not a policy bypass (a client without the token cannot enumerate them).
		"enterpriseAdministratorInvitationByToken": "secret invitation-token-gated; the token is the authorization",
		"enterpriseMemberInvitationByToken":        "secret invitation-token-gated; the token is the authorization",
	}

	var unclassified []string
	for _, f := range sch.schema.Query.Fields {
		name := f.Name
		if strings.HasPrefix(name, "__") {
			continue // introspection (__schema/__type/__typename) → classifier maps to the meta category
		}
		if classifierScopedRoots[name] {
			continue
		}
		if _, ok := publicSafeRoots[name]; ok {
			continue
		}
		unclassified = append(unclassified, name)
	}
	if len(unclassified) > 0 {
		sort.Strings(unclassified)
		t.Fatalf("%d Query root field(s) are neither classifier-scoped nor in the public/safe allowlist — "+
			"if a new one returns owner-private non-repo data it leaks under Defaults.Mode=allow (the "+
			"response filter is repo-centric). Scope it in collectGraphQLScopes or justify it in "+
			"publicSafeRoots:\n  %s", len(unclassified), strings.Join(unclassified, "\n  "))
	}
}
