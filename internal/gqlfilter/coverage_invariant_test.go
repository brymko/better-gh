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
