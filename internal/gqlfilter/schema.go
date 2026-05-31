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

// Schema wraps GitHub's GraphQL schema plus the derived repo-scoped type paths.
type Schema struct {
	schema           *ast.Schema
	repoScoped       map[string]bool     // type name -> belongs to a single repository
	repoPath         map[string][]string // type name -> no-arg field path to its repo's nameWithOwner
	nodeResolveQuery string              // nodes(ids:) query covering every repo-scoped Node type
}

// crossRepoNavFields are singular fields that point to a DIFFERENT repository than the
// object's own (a fork's parent/source, a PR's head/base repo, a template). The repo-path
// derivation must not follow them, or a type could be attributed to — and redacted
// against — the wrong repository.
var crossRepoNavFields = map[string]bool{
	"parent": true, "source": true, "headRepository": true,
	"baseRepository": true, "templateRepository": true,
}

// Load parses the embedded GitHub schema and derives, for every type that belongs to a
// single repository, the no-arg field path that reaches that repository's nameWithOwner
// (see deriveRepoPaths). A type is repo-scoped iff it has such a path. This is what lets
// the response filter tag (and the resolver identify) the repository of types that link to
// it indirectly — e.g. DiscussionComment, whose only link is `discussion` → Discussion →
// repository (GitHub gives it no direct `repository` field, unlike IssueComment).
func Load() (*Schema, error) {
	s, err := gqlparser.LoadSchema(&ast.Source{Name: "github.graphql", Input: schemaSDL})
	if err != nil {
		return nil, fmt.Errorf("loading github schema: %w", err)
	}
	paths := deriveRepoPaths(s)
	rs := make(map[string]bool, len(paths))
	for name := range paths {
		rs[name] = true
	}
	sch := &Schema{schema: s, repoScoped: rs, repoPath: paths}
	q := sch.buildNodeResolveQuery()
	if _, gerr := gqlparser.LoadQuery(s, q); gerr != nil {
		return nil, fmt.Errorf("building node-resolve query: %s", gerr.Error())
	}
	sch.nodeResolveQuery = q
	return sch, nil
}

// deriveRepoPaths maps each single-repository type to the no-arg field path reaching its
// repository's nameWithOwner. Seeds: Repository → [nameWithOwner]; a type with a no-arg
// `repository: Repository` MEMBERSHIP field → [repository, nameWithOwner] (a
// `repository(name:)` LOOKUP field takes arguments and is excluded). Then it transitively
// follows no-arg SINGULAR membership fields to an already-pathed type (DiscussionComment.
// discussion → Discussion's path), skipping list/argumented/cross-repo-nav fields so the
// path always lands on the object's OWN repository.
func deriveRepoPaths(schema *ast.Schema) map[string][]string {
	paths := map[string][]string{}
	if _, ok := schema.Types["Repository"]; ok {
		paths["Repository"] = []string{"nameWithOwner"}
	}
	for name, def := range schema.Types {
		if name == "Repository" || (def.Kind != ast.Object && def.Kind != ast.Interface) {
			continue
		}
		for _, f := range def.Fields {
			if f.Name == "repository" && f.Type.Name() == "Repository" && len(f.Arguments) == 0 {
				paths[name] = []string{"repository", "nameWithOwner"}
				break
			}
		}
	}
	const maxHops = 3 // bound transitive depth; real membership chains are 1 hop
	for i := 0; i < maxHops; i++ {
		changed := false
		for name, def := range schema.Types {
			if _, has := paths[name]; has {
				continue
			}
			if def.Kind != ast.Object && def.Kind != ast.Interface {
				continue
			}
			var best []string
			for _, f := range def.Fields {
				// no-arg, singular (Elem==nil → not a list), non-nav membership fields only
				if len(f.Arguments) != 0 || f.Type.Elem != nil || crossRepoNavFields[f.Name] {
					continue
				}
				if tp, ok := paths[f.Type.Name()]; ok && (best == nil || len(tp)+1 < len(best)) {
					best = append([]string{f.Name}, tp...)
				}
			}
			if best != nil {
				paths[name] = best
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return paths
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
// implements Node (only Node types can be returned by nodes(ids:)), each reporting its
// repository's nameWithOwner along that type's derived path (Repository reports its own;
// others walk repository{…} or, e.g., discussion{repository{…}}).
func (s *Schema) buildNodeResolveQuery() string {
	nodeImpl := make(map[string]bool)
	for _, d := range s.schema.PossibleTypes["Node"] {
		nodeImpl[d.Name] = true
	}
	var names []string
	for name := range s.repoPath {
		def := s.schema.Types[name]
		if def != nil && def.Kind == ast.Object && nodeImpl[name] {
			names = append(names, name)
		}
	}
	sort.Strings(names) // deterministic output
	// Each fragment aliases its path uniquely (bghr0, bghr1, ...): the field's nullability
	// differs across types and a shared response key would fail GraphQL's field-merge
	// validation. The proxy reads whichever marker key is present (only the matching
	// fragment executes per node) and finds nameWithOwner at any depth.
	var b strings.Builder
	b.WriteString("query($ids:[ID!]!){nodes(ids:$ids){__typename")
	for i, n := range names {
		b.WriteString(" ... on " + n + "{" + renderPathSelection("bghr"+strconv.Itoa(i), s.repoPath[n]) + "}")
	}
	b.WriteString("}}")
	return b.String()
}

// renderPathSelection renders a repo path as an aliased nested GraphQL selection, e.g.
// path [discussion repository nameWithOwner] → "bghr0:discussion{repository{nameWithOwner}}".
func renderPathSelection(alias string, path []string) string {
	var b strings.Builder
	b.WriteString(alias)
	b.WriteByte(':')
	for i, p := range path {
		b.WriteString(p)
		if i < len(path)-1 {
			b.WriteByte('{')
		}
	}
	b.WriteString(strings.Repeat("}", len(path)-1))
	return b.String()
}
