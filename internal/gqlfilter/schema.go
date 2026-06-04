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
	"github.com/vektah/gqlparser/v2/validator/rules"
)

//go:embed schema.graphql
var schemaSDL string

// pathStep is one hop in a type's path to its repository's nameWithOwner. field is the field to
// select; onType, when set, narrows the field's subselection to `... on <onType>` — needed when
// the link is a union/interface (e.g. RepositoryRuleset.source: RuleSource → `... on Repository`).
type pathStep struct {
	field  string
	onType string
}

// Schema wraps GitHub's GraphQL schema plus the derived repo-scoped type paths.
type Schema struct {
	schema           *ast.Schema
	repoScoped       map[string]bool       // type name -> has a marker/resolve path to a single repository
	repoPath         map[string][]pathStep // type name -> no-arg field path to its repo's nameWithOwner
	nodeResolveQuery string                // nodes(ids:) query covering every repo-scoped Node type
	typeRes          map[string]string     // object type -> per-resource policy key (derived from @docsCategory + overrides)
	nodeTypes        map[string]bool       // object types implementing Node (recognized by this snapshot)
	repoOwnedNoPath  map[string]bool       // Node object types that belong to a repo (by @docsCategory) but have NO derivable repoPath
	validationRules  *rules.Rules          // default validation rules MINUS the O(n^2) OverlappingFieldsCanBeMerged (see Augment)
}

// repoOwnedCategories are @docsCategory values whose objects belong to exactly ONE repository. A
// Node OBJECT type in one of these categories that has no derivable repoPath (its only repo link
// is an argumented connection, or a union/interface whose members are repo-scoped types other than
// Repository itself) can neither be tagged by the response filter NOR attributed by the node
// resolver — so a node(id:)/nodes(ids:) reference to it must fail CLOSED rather than be treated as a
// constraint-free non-repo node (round-16: Workflow/DeployKey/ClosedEvent/DeploymentReview/
// RepositoryTopic/RepositoryCustomProperty leaked a denied repo's data/identity/oracle). The set is
// deliberately limited to categories that are unambiguously single-repo-owned; ambiguous categories
// (orgs/users/projects/packages/security-advisories/…) are excluded so legitimate non-repo node
// reads are not denied. Erring here costs availability (a denied node read), never a leak.
var repoOwnedCategories = map[string]bool{
	"issues": true, "pulls": true, "commits": true, "branches": true,
	"deployments": true, "actions": true, "checks": true, "releases": true,
	"git": true, "deploy-keys": true, "discussions": true,
	"dependency-graph": true, "repos": true,
}

// deriveRepoOwnedNoPath returns the Node OBJECT types whose @docsCategory marks them as belonging to
// a single repository but for which deriveRepoPaths found NO path to that repository. Deriving from
// @docsCategory (not a hand-maintained list) means a schema refresh that introduces another such
// type is covered automatically — the node resolver fails it closed.
func deriveRepoOwnedNoPath(schema *ast.Schema, repoPath map[string][]pathStep) map[string]bool {
	nodeImpl := map[string]bool{}
	for _, d := range schema.PossibleTypes["Node"] {
		if d.Kind == ast.Object {
			nodeImpl[d.Name] = true
		}
	}
	out := map[string]bool{}
	for name, def := range schema.Types {
		if def.Kind != ast.Object || !nodeImpl[name] {
			continue
		}
		if _, pathed := repoPath[name]; pathed {
			continue // resolvable/markable already
		}
		if d := def.Directives.ForName("docsCategory"); d != nil {
			if arg := d.Arguments.ForName("name"); arg != nil && arg.Value != nil && repoOwnedCategories[arg.Value.Raw] {
				out[name] = true
			}
		}
	}
	return out
}

// docsCategoryResource maps GitHub's schema @docsCategory(name:) to the proxy's per-resource policy
// key, for the categories that correspond to a real per-resource permission. Categories with no
// dedicated key (repos/orgs/users/projects/discussions/reactions/packages/dependabot/security-
// advisories/…) are absent, so such a type falls to "metadata" (base access) — the documented
// residual for no-per-resource-key types. Deriving from the schema (instead of a hand-maintained
// type list) is what closes the round-15 gap where repo-scoped types with a real category
// (Environment→deployments, WorkflowRun→actions, Milestone/Label→issues, PullRequestThread→pulls,
// branchProtectionRules→branches, …) silently mapped to "metadata" and dodged a per-resource rule.
var docsCategoryResource = map[string]string{
	"pulls":       "pulls",
	"issues":      "issues",
	"commits":     "commits",
	"branches":    "branches",
	"deployments": "deployments",
	"actions":     "actions",
	"checks":      "checks",
	"releases":    "releases",
	"git":         "contents", // git objects (blobs/trees/tags) expose file content; ref-like types overridden below
}

// typeResourceOverride pins types whose @docsCategory names a different axis than the policy
// taxonomy: commit STATUSES are the proxy's "checks" resource (docsCategory "commits", matching the
// REST `statuses`→checks mapping); a git Ref is "branches" (docsCategory "git", matching /git/refs→
// branches and the REST `branches` surface). Overrides win over the docsCategory-derived value.
var typeResourceOverride = map[string]string{
	"Status":            "checks",
	"StatusContext":     "checks",
	"StatusCheckRollup": "checks",
	"Ref":               "branches",
}

// deriveTypeResources builds the object-type → per-resource-key map from the embedded schema's
// @docsCategory directives, applying typeResourceOverride first. A type with no mapped category is
// omitted (→ "metadata" at lookup). See docsCategoryResource.
func deriveTypeResources(schema *ast.Schema) map[string]string {
	out := map[string]string{}
	for name, def := range schema.Types {
		if def.Kind != ast.Object {
			continue
		}
		if r, ok := typeResourceOverride[name]; ok {
			out[name] = r
			continue
		}
		if d := def.Directives.ForName("docsCategory"); d != nil {
			if arg := d.Arguments.ForName("name"); arg != nil && arg.Value != nil {
				if r, ok := docsCategoryResource[arg.Value.Raw]; ok {
					out[name] = r
				}
			}
		}
	}
	return out
}

// deriveNodeObjectTypes is the set of OBJECT types that implement Node (the only types nodes(ids:)
// can return). The node resolver uses it to fail closed on a node whose runtime __typename the
// embedded snapshot does not recognize (live schema drift) rather than treating it as a
// constraint-free non-repo node (round-15).
func deriveNodeObjectTypes(schema *ast.Schema) map[string]bool {
	out := map[string]bool{}
	for _, d := range schema.PossibleTypes["Node"] {
		if d.Kind == ast.Object {
			out[d.Name] = true
		}
	}
	return out
}

// crossRepoNavFields are singular fields that point to a DIFFERENT repository than the
// object's own (a fork's parent/source, a PR's head repo, a template). The repo-path
// derivation must not follow them, or a type could be attributed to — and redacted
// against — the wrong repository.
//
// The Repository-typed links are joined by the head-side Ref/GitObject links: a PR/comparison's
// head ref/target can live in a FORK. Following headRef mis-attributed HeadRefDeletedEvent to the
// fork (audit round-14 hardening) — wrong-repo over-redaction today, a latent leak under schema
// drift. The own-repo side (baseRef/baseTarget/mergeCommit — a PR's base/merge are in the repo
// itself) is intentionally NOT excluded, so own-repo-only types (Comparison, MergeBranchPayload)
// keep their correct path; types whose ONLY link is head-side become non-repo-scoped and are gated
// by their already-tagged parent (the PR's Repository container), which is sound.
var crossRepoNavFields = map[string]bool{
	"parent": true, "source": true, "headRepository": true,
	"baseRepository": true, "templateRepository": true,
	"headRef": true, "headTarget": true,
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
	sch.typeRes = deriveTypeResources(s)
	sch.nodeTypes = deriveNodeObjectTypes(s)
	sch.repoOwnedNoPath = deriveRepoOwnedNoPath(s, paths)
	// Build the validation rule set Augment uses ONCE: the default rules minus
	// OverlappingFieldsCanBeMerged. That rule is O(n^2) in the number of fields sharing a response
	// name within a selection set (it compares every pair and recurses into their sub-selections with
	// no field-pair memoization), so a ~100KB query of same-aliased siblings — well under the token
	// cap — drove gqlparser.LoadQuery to multiple seconds of CPU on the request path BEFORE the policy
	// deny, a single-token DoS (round-17). The proxy does not need merge-conflict diagnostics: it only
	// augments + forwards, and GitHub re-validates the (un-augmented-semantics) document upstream and
	// returns an error response the filter handles. Dropping the rule removes the quadratic at its
	// source; the Walk still populates field.Definition (which augment needs) regardless of rules, and
	// every other default rule (unknown field/argument/type, fragment cycles, …) still runs.
	vr := rules.NewDefaultRules()
	vr.RemoveRule("OverlappingFieldsCanBeMerged")
	sch.validationRules = vr
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
func deriveRepoPaths(schema *ast.Schema) map[string][]pathStep {
	paths := map[string][]pathStep{}
	if _, ok := schema.Types["Repository"]; ok {
		paths["Repository"] = []pathStep{{field: "nameWithOwner"}}
	}
	for name, def := range schema.Types {
		if name == "Repository" || (def.Kind != ast.Object && def.Kind != ast.Interface) {
			continue
		}
		for _, f := range def.Fields {
			if f.Name == "repository" && f.Type.Name() == "Repository" && len(f.Arguments) == 0 {
				paths[name] = []pathStep{{field: "repository"}, {field: "nameWithOwner"}}
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
			var best []pathStep
			consider := func(cand []pathStep) {
				if best == nil || len(cand) < len(best) {
					best = cand
				}
			}
			for _, f := range def.Fields {
				if len(f.Arguments) != 0 || f.Type.Elem != nil {
					continue // argumented or list → not a singular own-repo membership
				}
				ft := f.Type.Name()
				if tp, ok := paths[ft]; ok {
					// Singular membership to an already-pathed CONCRETE type. Skip the cross-repo-
					// nav fields (Repository.parent/source/headRepository/… point to a DIFFERENT
					// repo); this exclusion is keyed on the concrete Repository link below.
					if crossRepoNavFields[f.Name] {
						continue
					}
					consider(append([]pathStep{{field: f.Name}}, tp...))
				} else if repoIsMemberOfAbstract(schema, ft) {
					// Singular field to a union/interface that has Repository as a concrete member
					// (e.g. RepositoryRuleset.source: RuleSource = Enterprise|Organization|Repository).
					// This is the object's OWN repository — reached by narrowing to `... on
					// Repository`. It cannot mis-attribute to a fork parent (that link is concrete
					// Repository-typed and excluded above), and a non-Repository source yields no
					// nameWithOwner → the node has no repo → redacted/denied (fail closed). This is
					// what makes union-linked Node types (round-12 H5) taggable and resolvable.
					consider(append([]pathStep{{field: f.Name, onType: "Repository"}}, paths["Repository"]...))
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

// repoIsMemberOfAbstract reports whether typeName is a union/interface that has Repository as a
// concrete possible type, so a singular field of that type can be narrowed to the object's own
// repository via `... on Repository { nameWithOwner }`.
func repoIsMemberOfAbstract(schema *ast.Schema, typeName string) bool {
	def := schema.Types[typeName]
	if def == nil || (def.Kind != ast.Union && def.Kind != ast.Interface) {
		return false
	}
	for _, pt := range schema.PossibleTypes[typeName] {
		if pt.Name == "Repository" {
			return true
		}
	}
	return false
}

func (s *Schema) isRepoScoped(typeName string) bool { return s.repoScoped[typeName] }

// IsRepoScopedType reports whether a GraphQL type has a derivable marker/resolve path to its
// single repository (so the response filter tags it and the node resolver can fetch its repo).
// It now also covers types whose only repo link is a union/interface source (e.g.
// RepositoryRuleset), which previously slipped through as non-repo nodes (round-12 audit H5).
// The proxy's node resolver uses it to fail closed if such a node resolves without a repository.
func (s *Schema) IsRepoScopedType(typeName string) bool { return s.repoScoped[typeName] }

// IsRepoOwnedUnattributableNodeType reports whether typename is a Node OBJECT type that belongs to a
// single repository (by @docsCategory) but has NO derivable path to that repository, so the node
// resolver cannot attribute it and the response filter cannot tag it. The proxy fails such a
// node(id:)/nodes(ids:) reference CLOSED instead of treating it as a constraint-free non-repo node
// (round-16). It is disjoint from IsRepoScopedType (those HAVE a path): a type satisfies at most one.
func (s *Schema) IsRepoOwnedUnattributableNodeType(typeName string) bool {
	return s.repoOwnedNoPath[typeName]
}

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
// [discussion repository nameWithOwner] → "bghr0:discussion{repository{nameWithOwner}}", and a
// union step [{source,Repository} {nameWithOwner}] → "bghr0:source{... on Repository{nameWithOwner}}".
func renderPathSelection(alias string, path []pathStep) string {
	var b strings.Builder
	b.WriteString(alias)
	b.WriteByte(':')
	closers := 0
	for i, p := range path {
		b.WriteString(p.field)
		if i < len(path)-1 {
			b.WriteByte('{')
			closers++
			if p.onType != "" {
				b.WriteString("... on ")
				b.WriteString(p.onType)
				b.WriteByte('{')
				closers++
			}
		}
	}
	b.WriteString(strings.Repeat("}", closers))
	return b.String()
}
