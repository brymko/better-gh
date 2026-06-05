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
	schema             *ast.Schema
	repoScoped         map[string]bool       // type name -> has a marker/resolve path to a single repository
	repoPath           map[string][]pathStep // type name -> no-arg field path to its repo's nameWithOwner
	nodeResolveQuery   string                // nodes(ids:) query covering every repo-scoped Node type
	typeRes            map[string]string     // object type -> per-resource policy key (derived from @docsCategory + overrides)
	nodeTypes          map[string]bool       // object types implementing Node (recognized by this snapshot)
	repoOwnedNoPath    map[string]bool       // concrete OBJECT types (Node or not) that belong to a repo (by @docsCategory) but have NO derivable repoPath
	repoIdentityNoPath map[string]bool       // Node types exposing a repo-identity scalar (nameWithOwner) but neither repoScoped nor repoOwnedNoPath
	repoIdentityScalar map[string]string     // repoIdentityNoPath type -> its repo-identity scalar field ("nameWithOwner" preferred; else "repositoryName")
	ownerOwnedNode     map[string]bool       // Node object types owned by an org/user/enterprise (not a repo, not public) — node(id:) reads fail closed
	validationRules    *rules.Rules          // default validation rules MINUS the O(n^2) OverlappingFieldsCanBeMerged (see Augment)
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

// deriveRepoOwnedNoPath returns the concrete OBJECT types whose @docsCategory marks them as
// belonging to a single repository but for which deriveRepoPaths found NO path to that repository.
// This is NOT restricted to Node implementors: many repo-owned CONTENT objects are embedded leaves
// that do not implement Node (Submodule→contents, IssueTemplate→issues, PullRequestChangedFile→pulls,
// CheckAnnotation→checks, ContributingGuidelines/RepositoryCodeowners→contents, the ruleset
// *Parameters types, …). Before round-18 the Node gate excluded them, so they received NO marker in
// augment() and the response filter forwarded them verbatim — bypassing a per-resource `none` on any
// object reached by navigation (e.g. repository{submodules{gitUrl}} leaked .gitmodules under
// contents="none"). Including them lets augment() inject a type-only marker so the filter attributes
// each to its nearest marked ancestor's repository and enforces s.FilterResource(type) there
// (fail-closed when no ancestor repo). Deriving from @docsCategory (not a hand-maintained list) means
// a schema refresh that introduces another such type is covered automatically. The node resolver,
// which also reads this set (IsRepoOwnedUnattributableNodeType), only ever sees Node typenames, so the
// added non-Node entries never change its behavior — they only widen the response filter's coverage.
func deriveRepoOwnedNoPath(schema *ast.Schema, repoPath map[string][]pathStep) map[string]bool {
	out := map[string]bool{}
	for name, def := range schema.Types {
		if def.Kind != ast.Object {
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

// ownerOwnedNodeCategories are @docsCategory values whose Node OBJECT types expose ORG/USER/ENTERPRISE-
// private data (members/emails, project items, audit entries, sponsorships, migrations, team data)
// rather than a repository or globally-public data. They are deliberately EXCLUDED from
// repoOwnedCategories (which is repo-only). A node(id:)/nodes(ids:) read of such a type is NOT
// repo-attributable, so neither the classifier scopes it nor the repo-only response filter redacts it;
// under default=allow an empty-scope read of one bypasses an [[org]] deny — the owner-level parallel
// of the round-16 repo-node bypass (round-20). The node resolver fails these closed, so an org/user/
// project is read via the SCOPED organization(login:)/user(login:) roots, which ARE policy-checked and
// response-filtered. The set is limited to unambiguously owner-private categories so genuinely public
// node types (licenses/code-of-conduct/marketplace/apps/…) are not over-denied.
var ownerOwnedNodeCategories = map[string]bool{
	"orgs": true, "teams": true, "projects": true, "projects-classic": true,
	"enterprise-admin": true, "migrations": true, "sponsors": true, "users": true,
	// gists: a Gist/GistComment is user/owner-PRIVATE (a secret gist's files), not repo-attributable,
	// and separately policy-gated (REST /gists → the `gists` unscoped category). Without this a
	// node(id:Gist) read bypassed a gists carve-out under default=allow — the round-20 owner-owned
	// fix's missed sibling category (round-21). Read a gist via the policy-checked viewer{gists} /
	// user(login:){gists} roots instead.
	"gists": true,
}

// deriveOwnerOwnedNodes returns Node OBJECT types whose @docsCategory marks them as owner-private
// (ownerOwnedNodeCategories) and that are NOT repo-attributable (so the repo resolver/filter cannot
// gate them). The node resolver fails a node(id:) reference to one closed (round-20).
func deriveOwnerOwnedNodes(schema *ast.Schema, repoScoped, repoOwnedNoPath map[string]bool) map[string]bool {
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
		if repoScoped[name] || repoOwnedNoPath[name] {
			continue
		}
		if d := def.Directives.ForName("docsCategory"); d != nil {
			if arg := d.Arguments.ForName("name"); arg != nil && arg.Value != nil && ownerOwnedNodeCategories[arg.Value.Raw] {
				out[name] = true
			}
		}
	}
	return out
}

// repoIdentityScalars are field names that expose a repository's identity directly on a node as a
// scalar (no navigation), so a node carrying one discloses a repo's name even when it has no field
// PATH to a Repository object the resolver/filter could attribute. nameWithOwner is "owner/repo"
// (fully attributable); repositoryName is a BARE repo name (no owner) the response filter cannot turn
// into a policy (owner, repo) on its own, so a type whose only such scalar is repositoryName is
// response-tagged with a TYPE marker and fails closed under a non-repo (e.g. org) scope.
var repoIdentityScalars = map[string]bool{"nameWithOwner": true, "repositoryName": true}

// deriveRepoIdentityNoPath returns Node OBJECT types that expose a repository-identifying SCALAR
// (nameWithOwner/repositoryName) directly on the node yet are NEITHER repoScoped (no derivable repo
// path to tag/resolve) NOR repoOwnedNoPath (not a per-resource content object) — e.g. the
// enterprise/migration namespace types EnterpriseRepositoryInfo, UserNamespaceRepository,
// RepositoryMigration. A node(id:) reference to one resolves to no repository and gets no response
// marker, so before round-18 it was treated as a constraint-free non-repo node and leaked a denied
// repo's name/visibility under default=allow. The node resolver fails these CLOSED instead. Their
// @docsCategory (enterprise-admin/migrations) is NOT single-repo-owned in general, so they cannot be
// folded into repoOwnedCategories without over-denying legitimate non-repo node reads.
func deriveRepoIdentityNoPath(schema *ast.Schema, repoScoped, repoOwnedNoPath map[string]bool) map[string]string {
	nodeImpl := map[string]bool{}
	for _, d := range schema.PossibleTypes["Node"] {
		if d.Kind == ast.Object {
			nodeImpl[d.Name] = true
		}
	}
	out := map[string]string{}
	for name, def := range schema.Types {
		if def.Kind != ast.Object || !nodeImpl[name] {
			continue
		}
		if repoScoped[name] || repoOwnedNoPath[name] {
			continue
		}
		scalar := ""
		for _, f := range def.Fields {
			if repoIdentityScalars[f.Name] && f.Type.Elem == nil && f.Type.Name() == "String" {
				// Prefer nameWithOwner (fully attributable "owner/repo") over a bare repositoryName.
				if f.Name == "nameWithOwner" {
					scalar = f.Name
					break
				}
				if scalar == "" {
					scalar = f.Name
				}
			}
		}
		if scalar != "" {
			out[name] = scalar
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
	// deploy-keys → "keys": DeployKey (@docsCategory deploy-keys) exposes the public key material,
	// title, and read/write flag the REST `keys`/`deploy-keys` resource gates (restResourceMap). Without
	// this entry FilterResource("DeployKey") fell to "metadata", so repository{deployKeys{…}} navigation
	// authorized against base access and bypassed a keys="none" carve-out the direct GET /repos/{o}/{r}/
	// keys (and the node(id:DeployKey) resolver) enforce — round-20. Keeps the per-resource axis identical
	// on REST and GraphQL for this key.
	"deploy-keys": "keys",
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
	// RefUpdateRule (@docsCategory "git" → would derive "contents") is the effective branch-protection
	// rule for a ref (allowsForcePushes/requiredApprovingReviewCount/requiredStatusCheckContexts/…), the
	// "branches" resource — like its sibling BranchProtectionRule and Ref. It is reachable only via the
	// branches-gated Ref.refUpdateRule today (so masked), but pinning it keeps the per-resource axis
	// correct if a future schema adds a non-branches path to it (round-20). Guarded by the extended
	// repoOwnedNoPath resource invariant below.
	"RefUpdateRule": "branches",
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
//
// The cross-repo ISSUE-RELATION links (subIssue/blockingIssue/blockedIssue) point to a RELATED
// issue that may live in a different repository (a sub-issue or a blocking/blocked issue can be
// cross-repo). The timeline events whose ONLY repo link is one of these (SubIssueAdded/RemovedEvent,
// Blocking/BlockedBy*Event) therefore have no own-repo path and fall to repoOwnedNoPath (ambient-
// attributed + node-denied), exactly like CrossReferencedEvent; the *Payload types that ALSO carry
// `issue` (the modified issue) keep deriving via that own link. Following the relation link instead
// attributed the event to a foreign repo and leaked its metadata (round-19 F2).
//
// fromRepository (TransferredEvent's source repo) is listed for clarity, though the general
// "direct Repository field must be named `repository`" rule in deriveRepoPaths already excludes it.
var crossRepoNavFields = map[string]bool{
	"parent": true, "source": true, "headRepository": true,
	"baseRepository": true, "templateRepository": true,
	"headRef": true, "headTarget": true,
	"fromRepository": true,
	"subIssue":       true, "blockingIssue": true, "blockedIssue": true,
}

// crossRepoNavByType excludes a link only on SPECIFIC types where it is cross-repo, because the
// SAME field name is an own-repo link on other types and must not be excluded globally:
//   - ReferencedEvent.commit / .commitRepository — the REFERENCING commit and its repo, which
//     "originated in a different repository" (sibling isCrossRepository). `commit` is own-repo on
//     BlameRange/PullRequestCommit/MergedEvent/Status/…, so it cannot be a global exclusion. With
//     both excluded, ReferencedEvent has no path → repoOwnedNoPath (ambient + node-deny).
//   - HeadRefForcePushedEvent.afterCommit / .beforeCommit — the HEAD-side commits of a force-push,
//     which live in the (possibly forked) head repo; the event itself belongs to the PR's base
//     repo, reached via the own `pullRequest` link. (BaseRefForcePushedEvent's after/beforeCommit
//     ARE own-repo — the base ref is in the repo itself — so they are NOT excluded.)
//   - PullRequestRevisionMarker.lastSeenCommit — a commit the viewer last saw, which can be a fork
//     commit; the marker belongs to the PR's repo via the own `pullRequest` link.
//
// round-19 F2.
var crossRepoNavByType = map[string]map[string]bool{
	"ReferencedEvent":           {"commit": true, "commitRepository": true},
	"HeadRefForcePushedEvent":   {"afterCommit": true, "beforeCommit": true},
	"PullRequestRevisionMarker": {"lastSeenCommit": true},
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
	sch.repoIdentityScalar = deriveRepoIdentityNoPath(s, rs, sch.repoOwnedNoPath)
	sch.repoIdentityNoPath = make(map[string]bool, len(sch.repoIdentityScalar))
	for name := range sch.repoIdentityScalar {
		sch.repoIdentityNoPath[name] = true
	}
	sch.ownerOwnedNode = deriveOwnerOwnedNodes(s, rs, sch.repoOwnedNoPath)
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
					// Singular membership to an already-pathed CONCRETE type. Skip cross-repo links
					// that point to a DIFFERENT repository than this object's own: the global denylist
					// (parent/source/headRepository/… and the cross-repo issue relations) and the
					// per-(type,field) links that are cross-repo only on some types.
					if crossRepoNavFields[f.Name] || crossRepoNavByType[name][f.Name] {
						continue
					}
					// A DIRECT Repository link is the object's OWN repo only when named `repository`
					// (the canonical membership the seed pass already handles). Every other
					// Repository-typed field is a foreign link by GitHub convention (fromRepository,
					// commitRepository, parent, source, head/base/templateRepository, an edge's node),
					// so never derive an own-repo path through it — doing so mis-attributes the object
					// to the WRONG repository and either leaks its metadata (when the foreign repo is
					// allowed) or over-redacts (round-19 F2). This general rule subsumes the direct-
					// Repository entries in crossRepoNavFields and bounds the whole class.
					if ft == "Repository" && f.Name != "repository" {
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

// IsRepoOwnedUnattributableNodeType reports whether typename is a concrete OBJECT type that belongs
// to a single repository (by @docsCategory) but has NO derivable path to that repository, so it
// cannot be tagged with its repo. The node resolver uses it to fail a node(id:)/nodes(ids:) reference
// CLOSED instead of treating it as a constraint-free non-repo node (round-16); since node IDs only
// resolve to Node types, the non-Node members of this set (added round-18 for response-filter
// coverage) never reach the resolver. It is disjoint from IsRepoScopedType (those HAVE a path).
func (s *Schema) IsRepoOwnedUnattributableNodeType(typeName string) bool {
	return s.repoOwnedNoPath[typeName]
}

// IsRepoIdentityUnattributableType reports whether typename is a Node OBJECT type that exposes a
// repository-identifying scalar (nameWithOwner/repositoryName) directly on the node but has no
// derivable repo path and is not a per-resource content type — so a node(id:) reference to it
// resolves to no repository and the response filter cannot tag it. The node resolver fails such a
// reference CLOSED rather than treat it as a constraint-free non-repo node, which would leak a
// denied repo's name/visibility under default=allow (round-18 H).
func (s *Schema) IsRepoIdentityUnattributableType(typeName string) bool {
	return s.repoIdentityNoPath[typeName]
}

// IsOwnerOwnedNodeType reports whether typename is a Node OBJECT type owned by an org/user/enterprise
// (Organization/Team/ProjectV2/audit entries/…) that exposes owner-private data and is not
// repo-attributable. The node resolver fails a node(id:)/nodes(ids:) reference to one CLOSED so an
// empty-scope read cannot bypass an [[org]] deny under default=allow (round-20); the data is reachable
// via the policy-checked organization(login:)/user(login:) roots instead.
func (s *Schema) IsOwnerOwnedNodeType(typeName string) bool {
	return s.ownerOwnedNode[typeName]
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
