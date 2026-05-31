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

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
)

//go:embed schema.graphql
var schemaSDL string

// Schema wraps GitHub's GraphQL schema plus the derived set of repo-scoped types.
type Schema struct {
	schema     *ast.Schema
	repoScoped map[string]bool // type name -> belongs to a single repository
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
	return &Schema{schema: s, repoScoped: rs}, nil
}

func (s *Schema) isRepoScoped(typeName string) bool { return s.repoScoped[typeName] }
