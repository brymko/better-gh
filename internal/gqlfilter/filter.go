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

// markerTypeAlias is injected alongside markerAlias as `bghRepoTypeZ9: __typename`, so the
// filter learns each repo-scoped object's RUNTIME type and can map it to a per-resource key
// (PullRequest→"pulls", Issue→"issues", …). This makes per-resource policy enforceable no
// matter how an object is reached — including navigating back to the same repo — which the
// repo-only marker cannot do (it is repo-granular). Stripped from the response like markerAlias.
const markerTypeAlias = "bghRepoTypeZ9"

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
			if key == markerAlias || key == markerTypeAlias {
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
		// Repo marker (which repository) + type marker (which resource), so the filter can
		// apply per-resource policy to this object regardless of how it was reached.
		*sels = append(*sels, s.marker(typeName), typenameMarker())
	}
}

// typenameMarker injects `bghRepoTypeZ9: __typename` so the filter can map the object's
// runtime type to a per-resource key. __typename is valid in every object/interface
// selection and adds negligible cost.
func typenameMarker() *ast.Field {
	return &ast.Field{Alias: markerTypeAlias, Name: "__typename"}
}

// marker builds the hidden repository-identifying field for a repo-scoped type, following
// that type's derived path (Repository → nameWithOwner; RepositoryNode → repository{
// nameWithOwner}; DiscussionComment → discussion{repository{nameWithOwner}}). The outermost
// field carries markerAlias so the filter/round-trip can find and strip it.
func (s *Schema) marker(typeName string) *ast.Field {
	path := s.repoPath[typeName]
	var field *ast.Field
	for i := len(path) - 1; i >= 0; i-- {
		f := &ast.Field{Name: path[i]}
		if field != nil {
			f.SelectionSet = ast.SelectionSet{field}
		}
		field = f
	}
	field.Alias = markerAlias
	return field
}

// Filter walks a GraphQL JSON response and redacts (replaces with null) any repo-scoped
// object the authorized predicate rejects, then strips the injected markers. authorized
// receives "owner", "repo", and the per-resource key derived from the object's runtime
// __typename (PullRequest→"pulls", Issue→"issues", …; "metadata" for the repository itself
// and unmapped types). Passing the resource lets per-resource policy (e.g. pulls="none") be
// enforced on objects reached by ANY path — navigation included — not just the entry point.
func Filter(resp map[string]any, authorized func(owner, repo, resource string) bool) map[string]any {
	v := filterValue(resp, authorized)
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func filterValue(v any, authorized func(owner, repo, resource string) bool) any {
	switch val := v.(type) {
	case map[string]any:
		if tag, ok := val[markerAlias]; ok {
			// A repo marker is only injected onto repo-scoped objects, so its presence means
			// this object belongs to a repository. Redact if that (repo, resource) is denied
			// OR if the marker is unparseable (anomalous null/malformed repository) — failing
			// closed, since we cannot prove the object is authorized. The resource comes from
			// the runtime type marker (markerTypeAlias); absent/unmapped → "metadata" (base).
			owner, repo, parsed := repoFromMarker(tag)
			resource := typeResource(markerTypename(val))
			if !parsed || !authorized(owner, repo, resource) {
				return nil
			}
			delete(val, markerAlias)
		}
		delete(val, markerTypeAlias) // strip the injected type marker (whether or not a repo marker rode with it)
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

// markerTypename returns the runtime __typename injected under markerTypeAlias, or "" if
// absent (which maps to the "metadata" resource — base access).
func markerTypename(val map[string]any) string {
	s, _ := val[markerTypeAlias].(string)
	return s
}

// gqlTypeToResource maps a GraphQL object's __typename to the per-resource policy key (the
// same keys internal/classifier and the policy engine use). A type not listed maps to
// "metadata", governed by the rule's base access — so unmapped objects keep the prior
// repo-granular behaviour and no over-broad resource restriction is applied. Only types
// with a single, unambiguous resource are listed.
var gqlTypeToResource = map[string]string{
	"PullRequest":              "pulls",
	"PullRequestReview":        "pulls",
	"PullRequestReviewComment": "pulls",
	"PullRequestReviewThread":  "pulls",
	"PullRequestCommit":        "pulls",
	"Issue":                    "issues",
	"IssueComment":             "issues",
	"Commit":                   "commits",
	"CommitComment":            "commits",
	"Release":                  "releases",
	"ReleaseAsset":             "releases",
	"Ref":                      "branches",
	"Deployment":               "deployments",
	"DeploymentStatus":         "deployments",
	"CheckRun":                 "checks",
	"CheckSuite":               "checks",
	// Commit statuses are the "checks" resource (the classifier maps REST `statuses`→checks).
	// They are reached via commit.status / commit.statusCheckRollup, whose parent Commit is a
	// DIFFERENT resource (commits), so without these a checks="none" rule would not redact
	// commit-status data (CI state, target URLs) read over GraphQL.
	"Status":            "checks",
	"StatusContext":     "checks",
	"StatusCheckRollup": "checks",
	"Tree":              "contents",
	"Blob":              "contents",
	// Branch protection config is the "branches" resource (REST: /branches/{b}/protection).
	// Reached directly via repository().branchProtectionRules, so it is gated only by repo
	// metadata unless mapped here.
	"BranchProtectionRule": "branches",
}

func typeResource(typename string) string {
	if r, ok := gqlTypeToResource[typename]; ok {
		return r
	}
	return "metadata"
}

// repoFromMarker extracts owner/repo from a marker value. The marker subtree contains only
// the path to a single nameWithOwner (a bare "owner/repo" string for Repository, or a
// nested object like {repository:{nameWithOwner:"owner/repo"}} or {discussion:{repository:
// {nameWithOwner:"owner/repo"}}}), so the repository is the one "owner/repo" string within.
func repoFromMarker(tag any) (owner, repo string, ok bool) {
	nwo := findNameWithOwner(tag)
	if i := strings.IndexByte(nwo, '/'); i > 0 && i < len(nwo)-1 {
		return nwo[:i], nwo[i+1:], true
	}
	return "", "", false
}

// findNameWithOwner returns the single "owner/repo" string within a marker value, recursing
// through the nested objects the marker path produces. A null/absent link (e.g. a comment
// whose discussion is null) yields "" → the caller redacts (fail closed).
func findNameWithOwner(v any) string {
	switch t := v.(type) {
	case string:
		if strings.Contains(t, "/") {
			return t
		}
	case map[string]any:
		for _, child := range t {
			if s := findNameWithOwner(child); s != "" {
				return s
			}
		}
	}
	return ""
}
