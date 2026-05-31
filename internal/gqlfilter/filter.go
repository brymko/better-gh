package gqlfilter

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/formatter"
)

// markerAlias is the response field injected into every repo-scoped object so it
// self-identifies its repository. A "__" prefix is reserved by GraphQL, so this uses a
// plain (collision-unlikely) alias.
const markerAlias = "bghRepoTagZ9"

// Augment validates a read query against the GitHub schema and injects, into every
// repo-scoped selection set, a hidden field revealing that object's repository. It
// returns the rewritten query. An invalid/untypable query yields an error so the
// caller can fail closed.
func (s *Schema) Augment(query string) (string, error) {
	doc, gerr := gqlparser.LoadQuery(s.schema, query)
	if gerr != nil {
		return "", fmt.Errorf("validating query: %s", gerr.Error())
	}
	// Fail closed if the client itself references the reserved marker alias: it could
	// otherwise pre-declare bghRepoTagZ9 in a repo-scoped selection to suppress our
	// injected repository tag and defeat redaction. The same walk bounds nesting depth so
	// augment() below never recurses unboundedly. The caller treats this error like an
	// untypable query, falling back to the classifier's cross-repo-nav denial.
	for _, op := range doc.Operations {
		if usesReservedAlias(op.SelectionSet, 0) {
			return "", fmt.Errorf("query references reserved alias %q or is too deeply nested", markerAlias)
		}
	}
	for _, frag := range doc.Fragments {
		if usesReservedAlias(frag.SelectionSet, 0) {
			return "", fmt.Errorf("query references reserved alias %q or is too deeply nested", markerAlias)
		}
	}
	for _, op := range doc.Operations {
		root := s.rootTypeName(op.Operation)
		s.augment(&op.SelectionSet, root)
	}
	for _, frag := range doc.Fragments {
		s.augment(&frag.SelectionSet, frag.TypeCondition)
	}

	var buf bytes.Buffer
	formatter.NewFormatter(&buf).FormatQueryDocument(doc)
	return buf.String(), nil
}

// maxAugmentDepth bounds the marker/alias walk; a query deeper than this fails closed.
// Real queries are far shallower, and GitHub itself rejects very deep documents.
const maxAugmentDepth = 256

// usesReservedAlias reports whether any field in the selection tree uses markerAlias as
// its response key (alias, or name when unaliased), or whether the tree exceeds
// maxAugmentDepth. Fragment bodies are checked via their own definitions by the caller,
// so fragment spreads are not followed here.
func usesReservedAlias(sels ast.SelectionSet, depth int) bool {
	if depth > maxAugmentDepth {
		return true
	}
	for _, sel := range sels {
		switch f := sel.(type) {
		case *ast.Field:
			key := f.Alias
			if key == "" {
				key = f.Name
			}
			if key == markerAlias {
				return true
			}
			if usesReservedAlias(f.SelectionSet, depth+1) {
				return true
			}
		case *ast.InlineFragment:
			if usesReservedAlias(f.SelectionSet, depth+1) {
				return true
			}
		}
	}
	return false
}

func (s *Schema) rootTypeName(op ast.Operation) string {
	switch op {
	case ast.Mutation:
		if s.schema.Mutation != nil {
			return s.schema.Mutation.Name
		}
	case ast.Subscription:
		if s.schema.Subscription != nil {
			return s.schema.Subscription.Name
		}
	}
	if s.schema.Query != nil {
		return s.schema.Query.Name
	}
	return "Query"
}

// augment recurses first (so injected markers are not themselves descended into), then
// appends the marker if this selection set's type is repo-scoped.
func (s *Schema) augment(sels *ast.SelectionSet, typeName string) {
	for _, sel := range *sels {
		switch f := sel.(type) {
		case *ast.Field:
			if f.Definition != nil && len(f.SelectionSet) > 0 {
				s.augment(&f.SelectionSet, f.Definition.Type.Name())
			}
		case *ast.InlineFragment:
			tc := f.TypeCondition
			if tc == "" {
				tc = typeName
			}
			s.augment(&f.SelectionSet, tc)
		}
	}
	if s.isRepoScoped(typeName) {
		*sels = append(*sels, s.marker(typeName))
	}
}

func (s *Schema) marker(typeName string) *ast.Field {
	if typeName == "Repository" {
		return &ast.Field{Alias: markerAlias, Name: "nameWithOwner"}
	}
	return &ast.Field{
		Alias: markerAlias,
		Name:  "repository",
		SelectionSet: ast.SelectionSet{
			&ast.Field{Alias: "nameWithOwner", Name: "nameWithOwner"},
		},
	}
}

// Filter walks a GraphQL JSON response and redacts (replaces with null) any repo-scoped
// object whose repository the authorized predicate rejects, then strips the injected
// markers. authorized receives "owner", "repo".
func Filter(resp map[string]any, authorized func(owner, repo string) bool) map[string]any {
	v := filterValue(resp, authorized)
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func filterValue(v any, authorized func(owner, repo string) bool) any {
	switch val := v.(type) {
	case map[string]any:
		if tag, ok := val[markerAlias]; ok {
			// A marker is only injected onto repo-scoped objects, so its presence means
			// this object belongs to a repository. Redact if that repository is denied OR
			// if the marker is unparseable (anomalous null/malformed repository) — failing
			// closed, since we cannot prove the object's repository is authorized.
			owner, repo, parsed := repoFromMarker(tag)
			if !parsed || !authorized(owner, repo) {
				return nil
			}
			delete(val, markerAlias)
		}
		for k, child := range val {
			val[k] = filterValue(child, authorized)
		}
		return val
	case []any:
		for i, child := range val {
			val[i] = filterValue(child, authorized)
		}
		return val
	default:
		return v
	}
}

// repoFromMarker extracts owner/repo from a marker value, which is either a string
// "owner/repo" (Repository) or an object {nameWithOwner:"owner/repo"} (RepositoryNode).
func repoFromMarker(tag any) (owner, repo string, ok bool) {
	var nwo string
	switch t := tag.(type) {
	case string:
		nwo = t
	case map[string]any:
		nwo, _ = t["nameWithOwner"].(string)
	}
	if i := strings.IndexByte(nwo, '/'); i > 0 && i < len(nwo)-1 {
		return nwo[:i], nwo[i+1:], true
	}
	return "", "", false
}
