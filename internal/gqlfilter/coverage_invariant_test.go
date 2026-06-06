package gqlfilter

import (
	"sort"
	"strings"
	"testing"

	"github.com/vektah/gqlparser/v2/ast"
)

// TestSchemaCoverageInvariant is the PERMANENT guard against the round-12 GraphQL bug class
// (interface/union/odd-link types silently treated as non-repo → fail OPEN). It enumerates the
// embedded schema and fails the BUILD if any type that is repo-scoped BY NATURE is not covered
// by the marker/resolve machinery (repoScoped) — using signals INDEPENDENT of deriveRepoPaths'
// own mechanism, so a derivation gap is caught here instead of by the next auditor.
//
// When GitHub adds a repo-bearing type and schema.graphql is refreshed, this test goes red until
// the type is either covered by deriveRepoPaths or added (with a documented reason) to one of the
// exception sets below. That converts a silent fail-open into a loud, must-resolve build failure.
func TestSchemaCoverageInvariant(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	sch := s.schema

	// Types we have deliberately decided are NOT single-repo-scoped, with the reason. A type
	// here is exempt from the invariants below. Keep this list short and justified.
	knownNotRepoScoped := map[string]string{
		"RepositoryOwner":      "interface for User|Organization — an owner of MANY repos, not one repo",
		"RepositoryConnection": "a connection/list wrapper, not a single repository",
		"RepositoryEdge":       "a connection edge; its node carries the repo (covered separately)",
		"RepositoryInfo":       "interface describing repo metadata; concrete Repository is covered",
	}

	var failures []string
	fail := func(name, why string) {
		failures = append(failures, name+": "+why)
	}

	for name, def := range sch.Types {
		if def.Kind != ast.Object {
			continue // only concrete object types can be returned by nodes(ids:) / appear at runtime
		}
		if _, exempt := knownNotRepoScoped[name]; exempt {
			continue
		}
		covered := s.repoScoped[name]

		// Signal A — implements RepositoryNode: GitHub's own marker that the type belongs to one
		// repository. Every such Object type MUST be covered.
		if implementsInterface(def, "RepositoryNode") && !covered {
			fail(name, "implements RepositoryNode but is not repo-scoped (uncovered by marker/resolve)")
			continue
		}

		// Signal B — a no-arg singular `repository: Repository` membership field (NOT an
		// argumented repository(name:) lookup, which is a navigator like User/Organization).
		if hasOwnRepositoryField(def) && !covered {
			fail(name, "has a no-arg `repository: Repository` membership field but is not repo-scoped")
			continue
		}

		// Signal C — a no-arg singular link to a union/interface that includes Repository (e.g.
		// RepositoryRuleset.source: RuleSource). This is exactly the round-12 H5 shape.
		if hasOwnAbstractRepoLink(sch, def) && !covered {
			fail(name, "has a no-arg singular union/interface link including Repository but is not repo-scoped")
			continue
		}
	}

	if len(failures) > 0 {
		sort.Strings(failures)
		t.Fatalf("schema coverage invariant violated — these repo-bearing types are not tagged/resolved "+
			"(fix deriveRepoPaths, or add to knownNotRepoScoped with a reason):\n  %s",
			strings.Join(failures, "\n  "))
	}
}

func implementsInterface(def *ast.Definition, iface string) bool {
	for _, i := range def.Interfaces {
		if i == iface {
			return true
		}
	}
	return false
}

// TestR18_RepoOwnedCategoryCoverageInvariant is the PERMANENT guard against the round-18 bug class:
// a concrete OBJECT type whose @docsCategory is an unambiguously repo-owned category (issues/pulls/
// commits/contents/checks/…) that is NEITHER repoScoped NOR repoOwnedNoPath would receive no marker
// in augment() and leak under a per-resource `none` (e.g. Submodule under contents="none"). Every
// such type MUST be covered by one of the two marker mechanisms. A schema refresh that introduces an
// uncovered repo-owned type fails the build here instead of silently fail-opening.
func TestR18_RepoOwnedCategoryCoverageInvariant(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	var failures []string
	for name, def := range s.schema.Types {
		if def.Kind != ast.Object {
			continue
		}
		d := def.Directives.ForName("docsCategory")
		if d == nil {
			continue
		}
		arg := d.Arguments.ForName("name")
		if arg == nil || arg.Value == nil || !repoOwnedCategories[arg.Value.Raw] {
			continue
		}
		if !s.repoScoped[name] && !s.repoOwnedNoPath[name] {
			failures = append(failures, name+" (@docsCategory "+arg.Value.Raw+")")
		}
	}
	if len(failures) > 0 {
		sort.Strings(failures)
		t.Fatalf("repo-owned-category OBJECT types covered by NEITHER repoScoped NOR repoOwnedNoPath "+
			"(they would leak under a per-resource `none` — fix deriveRepoPaths/deriveRepoOwnedNoPath):\n  %s",
			strings.Join(failures, "\n  "))
	}
}

// TestR20_RepoOwnedCategoryResourceMapping is the PERMANENT guard against the round-20 keys=none bug
// class: a repo-owned @docsCategory that corresponds to a real per-resource policy key but is MISSING
// from docsCategoryResource, so FilterResource() silently falls to "metadata" and a per-resource
// carve-out (e.g. keys=none on DeployKey, @docsCategory "deploy-keys") is bypassed by GraphQL
// navigation while the REST/direct-node paths enforce it. Every repoOwnedCategory must either map to a
// per-resource key in docsCategoryResource or be in the explicit "intentionally metadata" allowlist.
func TestR20_RepoOwnedCategoryResourceMapping(t *testing.T) {
	// Categories that legitimately have NO dedicated per-resource policy key, so their objects fall to
	// "metadata" (base access) by design — the documented no-per-resource-key residual.
	intentionallyMetadata := map[string]string{
		"discussions":      "no `discussions` policy key (documented residual)",
		"dependency-graph": "no `dependency-graph` policy key (dep/SBOM data gated by base/metadata)",
		"repos":            "the repository container/metadata itself",
		"reactions":        "no `reactions` policy key — a reaction is gated by its ambient repo's base/metadata access (round-41)",
	}
	for cat := range repoOwnedCategories {
		_, mapped := docsCategoryResource[cat]
		_, exempt := intentionallyMetadata[cat]
		if !mapped && !exempt {
			t.Errorf("repoOwnedCategory %q maps to NEITHER a docsCategoryResource per-resource key nor the "+
				"intentionally-metadata allowlist — its objects fall to \"metadata\" and bypass a per-resource "+
				"carve-out over GraphQL navigation (cf. round-20 deploy-keys). Add it to docsCategoryResource "+
				"(with its policy key) or intentionallyMetadata (with a reason).", cat)
		}
	}
}

// TestR20_RepoIdentityScalarCoverage is the PERMANENT guard against the round-20 repoIdentityNoPath
// navigation leak: a Node OBJECT type that exposes a repository-identity scalar (nameWithOwner/
// repositoryName) must be covered by one of augment()'s marker mechanisms (repoScoped, repoOwnedNoPath,
// or repoIdentityScalar) so navigating to it is tagged + redacted, not forwarded verbatim
// (RepositoryMigration/EnterpriseRepositoryInfo/UserNamespaceRepository leaked a denied repo's
// name/metadata under [[org]]-read before round-20).
func TestR20_RepoIdentityScalarCoverage(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	nodeImpl := map[string]bool{}
	for _, d := range s.schema.PossibleTypes["Node"] {
		if d.Kind == ast.Object {
			nodeImpl[d.Name] = true
		}
	}
	for name, def := range s.schema.Types {
		if def.Kind != ast.Object || !nodeImpl[name] {
			continue
		}
		hasIdentityScalar := false
		for _, f := range def.Fields {
			if repoIdentityScalars[f.Name] && f.Type.Elem == nil && f.Type.Name() == "String" {
				hasIdentityScalar = true
				break
			}
		}
		if !hasIdentityScalar {
			continue
		}
		if !s.repoScoped[name] && !s.repoOwnedNoPath[name] && s.repoIdentityScalar[name] == "" {
			t.Errorf("Node type %q exposes a repo-identity scalar but is covered by NO augment marker "+
				"mechanism (repoScoped/repoOwnedNoPath/repoIdentityScalar) — navigating to it forwards a repo "+
				"identity unredacted (round-20). Cover it in deriveRepoPaths/deriveRepoOwnedNoPath/"+
				"deriveRepoIdentityNoPath.", name)
		}
	}
}

func hasOwnRepositoryField(def *ast.Definition) bool {
	for _, f := range def.Fields {
		if f.Name == "repository" && len(f.Arguments) == 0 && f.Type.Elem == nil && f.Type.Name() == "Repository" {
			return true
		}
	}
	return false
}

func hasOwnAbstractRepoLink(sch *ast.Schema, def *ast.Definition) bool {
	for _, f := range def.Fields {
		if len(f.Arguments) != 0 || f.Type.Elem != nil {
			continue
		}
		if repoIsMemberOfAbstract(sch, f.Type.Name()) {
			return true
		}
	}
	return false
}
