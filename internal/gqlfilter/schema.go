// Package gqlfilter enforces per-repo policy on GraphQL by typing the client query
// against GitHub's real schema, injecting a hidden "which repository is this?" field
// into every repo-scoped selection, and redacting response objects whose repository
// the policy denies. This makes isolation sound regardless of how the query navigates
// (multi-root, owner.repositories, forks, search results, viewer.repositories, ...) —
// every repo-scoped datum is checked against its REAL repository, not a guessed one.
package gqlfilter

import (
	_ "embed"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
)

//go:embed schema.graphql
var schemaSDL string

// Schema wraps GitHub's GraphQL schema plus the derived set of repo-scoped types.
type Schema struct {
	schema           *ast.Schema
	repoScoped       map[string]bool // type name -> belongs to a single repository
	nodeResolveQuery string          // nodes(ids:) query covering every repo-scoped Node type
}

// Load parses the embedded GitHub schema and derives the repo-scoped type set: a type
// is repo-scoped if it is Repository itself, or it has a `repository: Repository`
// MEMBERSHIP field — one that takes no arguments (the RepositoryNode pattern: "the repo
// I belong to"). A `repository(name:)` LOOKUP field (on User/Organization/Query) takes
// arguments and does NOT make the owning type repo-scoped.
func Load() (*Schema, error) {
	s, err := gqlparser.LoadSchema(&ast.Source{Name: "github.graphql", Input: schemaSDL})
	if err != nil {
		return nil, fmt.Errorf("loading github schema: %w", err)
	}
	rs := make(map[string]bool)
	for name, def := range s.Types {
		if name == "Repository" {
			rs[name] = true
			continue
		}
		if def.Kind != ast.Object && def.Kind != ast.Interface {
			continue
		}
		for _, f := range def.Fields {
			if f.Name == "repository" && f.Type.Name() == "Repository" && len(f.Arguments) == 0 {
				rs[name] = true
				break
			}
		}
	}
	q := buildNodeResolveQuery(s, rs)
	if _, gerr := gqlparser.LoadQuery(s, q); gerr != nil {
		return nil, fmt.Errorf("building node-resolve query: %s", gerr.Error())
	}
	return &Schema{schema: s, repoScoped: rs, nodeResolveQuery: q}, nil
}

func (s *Schema) isRepoScoped(typeName string) bool { return s.repoScoped[typeName] }

// IsRepoScopedType reports whether a GraphQL type belongs to a single repository (so a
// node of that type must be authorized against that repo). The proxy's node resolver
// uses it to fail closed if a repo-scoped node resolves without yielding its repository.
func (s *Schema) IsRepoScopedType(typeName string) bool { return s.repoScoped[typeName] }

// NodeResolveQuery is a nodes(ids:) query that asks GitHub for each node's __typename and,
// for EVERY repo-scoped Node type, its repository's nameWithOwner. The proxy uses it to
// resolve referenced node IDs to their real repositories authoritatively. Generated from
// the schema (not a hand-maintained type list) so coverage tracks the embedded schema.
func (s *Schema) NodeResolveQuery() string { return s.nodeResolveQuery }

// buildNodeResolveQuery emits one inline fragment per repo-scoped OBJECT type that
// implements Node (only Node types can be returned by nodes(ids:)). Repository reports
// its own nameWithOwner; every other repo-scoped type reports repository{nameWithOwner}.
func buildNodeResolveQuery(schema *ast.Schema, repoScoped map[string]bool) string {
	nodeImpl := make(map[string]bool)
	for _, d := range schema.PossibleTypes["Node"] {
		nodeImpl[d.Name] = true
	}
	var names []string
	for name := range repoScoped {
		def := schema.Types[name]
		if def != nil && def.Kind == ast.Object && nodeImpl[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names) // deterministic output
	// Each fragment aliases its repository field uniquely (bghr0, bghr1, ...): the
	// repository field's nullability differs across types (Repository vs Repository!), and
	// a shared response key would fail GraphQL's field-merge validation. The proxy reads
	// whichever marker key is present (only the matching fragment executes per node).
	var b strings.Builder
	b.WriteString("query($ids:[ID!]!){nodes(ids:$ids){__typename")
	for i, n := range names {
		alias := "bghr" + strconv.Itoa(i)
		if n == "Repository" {
			b.WriteString(" ... on Repository{" + alias + ":nameWithOwner}")
		} else {
			b.WriteString(" ... on " + n + "{" + alias + ":repository{nameWithOwner}}")
		}
	}
	b.WriteString("}}")
	return b.String()
}
