package gqlfilter

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/formatter"
	"github.com/vektah/gqlparser/v2/parser"
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
	// Bound the parse before gqlparser.LoadQuery: LoadQuery re-parses with an UNLIMITED token
	// limit, which a deeply nested query drives into a fatal stack overflow before validation
	// ever runs (the same crash the classifier guards — Augment is reached on the request path
	// regardless of the classifier's verdict). A token-bounded pre-parse fails closed on such
	// input, and any query that passes it is small enough that LoadQuery's re-parse is bounded too.
	if _, perr := parser.ParseQueryWithTokenLimit(&ast.Source{Input: query}, maxAugmentTokens); perr != nil {
		return "", fmt.Errorf("parsing query: %s", perr.Error())
	}
	// Validate with the default rules MINUS OverlappingFieldsCanBeMerged (an O(n^2)-per-response-name
	// rule that is a CPU-DoS vector on the request path — see schema.go). The Walk still populates the
	// field definitions augment relies on, and all other rules still run, so an otherwise-invalid query
	// is still rejected and fails closed.
	doc, gerr := gqlparser.LoadQueryWithRules(s.schema, query, s.validationRules)
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
	// Bound the marker injection DURING construction. augment expands every abstract selection to
	// one inline fragment per repo-scoped concrete member (Node alone has ~130), so a query of
	// thousands of repeated abstract selections (node(id:){__typename}, ×thousands) would build a
	// ~200MB AST + tens of seconds of CPU BEFORE the post-serialization output cap below could
	// reject it — a single-client memory+CPU DoS (round-16, a surviving variant of round-15 F5
	// which bounded only the OUTPUT). The budget caps total injected fragments and short-circuits
	// the walk once exceeded, so the transient stays small; over the cap we fail closed (the caller
	// treats it like an untypeable query and the proxy denies).
	budget := &injectionBudget{remaining: maxAugmentInjections}
	for _, op := range doc.Operations {
		root := s.rootTypeName(op.Operation)
		s.augment(&op.SelectionSet, root, budget)
	}
	for _, frag := range doc.Fragments {
		s.augment(&frag.SelectionSet, frag.TypeCondition, budget)
	}
	if budget.exceeded {
		return "", fmt.Errorf("augmented query exceeds the marker-injection budget (%d fragments)", maxAugmentInjections)
	}

	var buf bytes.Buffer
	formatter.NewFormatter(&buf).FormatQueryDocument(doc)
	// Bound the augmented OUTPUT, not just the input token count. Marker injection adds one inline
	// fragment per repo-scoped concrete member of every abstract selection (Node alone has 100+),
	// so a small query of repeated abstract selections (node(id:){__typename}, ×thousands) can
	// expand ~600× — hundreds of MB / tens of seconds of CPU — before any authorization deny, a
	// single-process DoS reachable by any token holder (audit F5). Over the cap, fail closed: the
	// caller treats it like an untypable query and the proxy denies (respFilter==nil → deny).
	if buf.Len() > maxAugmentOutputBytes {
		return "", fmt.Errorf("augmented query too large (%d bytes > %d cap)", buf.Len(), maxAugmentOutputBytes)
	}
	return buf.String(), nil
}

// maxAugmentOutputBytes caps the rewritten query the proxy will forward. Real augmented queries
// are a few KB; this is far above any legitimate document yet bounds the marker-injection blowup.
const maxAugmentOutputBytes = 8 << 20 // 8 MB

// maxAugmentDepth bounds the marker/alias walk; a query deeper than this fails closed.
// Real queries are far shallower, and GitHub itself rejects very deep documents.
const maxAugmentDepth = 256

// maxAugmentInjections caps the total number of marker fragments augment may inject across the
// whole document, bounding the marker-injection blowup during construction (see Augment). Real
// augmented queries inject far fewer (one marker per repo-scoped selection); 50k fragments serialize
// to a few MB, well under maxAugmentOutputBytes, and build in milliseconds. Exceeding it fails closed.
const maxAugmentInjections = 50_000

// injectionBudget bounds how many marker fragments augment may inject. count() is called after each
// append; once the budget is exhausted, exceeded is set and the recursive walk short-circuits.
type injectionBudget struct {
	remaining int
	exceeded  bool
}

func (b *injectionBudget) count(n int) {
	b.remaining -= n
	if b.remaining < 0 {
		b.exceeded = true
	}
}

// maxAugmentTokens bounds Augment's pre-parse so gqlparser.LoadQuery's unlimited re-parse cannot
// stack-overflow on a deeply nested query. Matches the classifier's maxGraphQLTokens — far above
// any real query, far below the recursion depth that crashes the parser.
const maxAugmentTokens = 100_000

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
			if strings.HasPrefix(key, markerAlias) || strings.HasPrefix(key, markerTypeAlias) {
				// Reserve the whole marker namespace (exact aliases AND the per-member
				// "markerAlias_Type" suffixes augment injects), so a client cannot pre-declare a
				// look-alike key to spoof/suppress a repository tag and defeat redaction.
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
func (s *Schema) augment(sels *ast.SelectionSet, typeName string, budget *injectionBudget) {
	if budget.exceeded {
		return
	}
	for _, sel := range *sels {
		switch f := sel.(type) {
		case *ast.Field:
			if f.Definition != nil && len(f.SelectionSet) > 0 {
				s.augment(&f.SelectionSet, f.Definition.Type.Name(), budget)
			}
		case *ast.InlineFragment:
			tc := f.TypeCondition
			if tc == "" {
				tc = typeName
			}
			s.augment(&f.SelectionSet, tc, budget)
		}
		if budget.exceeded {
			return
		}
	}
	if s.isRepoScoped(typeName) {
		// Repo marker (which repository) + type marker (which resource), so the filter can
		// apply per-resource policy to this object regardless of how it was reached.
		*sels = append(*sels, s.marker(typeName), typenameMarker())
		budget.count(2)
		return
	}
	if s.repoOwnedNoPath[typeName] {
		// A repo-OWNED content type with NO derivable repository path (timeline events like
		// ClosedEvent/CrossReferencedEvent → issues/pulls, DeploymentReview → deployments,
		// IssueFieldSingleSelectOption → issues, …). We cannot tag its repository, but it is reached
		// by navigation from a SAME-repo marked ancestor, so inject ONLY the type marker; the response
		// filter attributes it to the nearest marked ancestor's repository and enforces its
		// per-resource policy there, failing closed if there is no ancestor repo (round-17). Without
		// this it carried NO marker at all and the filter forwarded it unredacted — bypassing e.g.
		// deployments/issues="none" on objects reached by navigation (the navigation analogue of the
		// round-16 node(id:) fail-closed, which only covered direct node-ID addressing).
		*sels = append(*sels, typenameMarker())
		budget.count(1)
		return
	}
	// Abstract type (interface/union): the runtime object is one of its concrete members.
	// Interfaces/unions are NEVER themselves repo-scoped (deriveRepoPaths only pathes concrete
	// types), so a selection written against the abstract type — `... on Comment { body }`,
	// `subject { ... }` where subject: ReferencedSubject, `node(id:){ ... }` — received no
	// marker and the filter forwarded a cross-repo object untagged (round-12 audit H1). Inject
	// a marker fragment for every repo-scoped concrete possibility, exactly as
	// buildNodeResolveQuery covers all repo-scoped Node types for nodes(ids:): whichever
	// concrete type comes back at runtime self-identifies its repository and gets redacted if
	// denied. Members that are not repo-scoped add nothing.
	members := s.repoScopedMembers(typeName)
	for _, member := range members {
		*sels = append(*sels, s.memberMarkerFragment(member))
	}
	budget.count(len(members))
	// Repo-owned-no-path members of the abstract type get a TYPE-only marker fragment (round-17),
	// so a selection that could resolve to one (e.g. an interface common field, or a union member
	// reached without an explicit inline fragment) is still attributed by the filter to its nearest
	// marked ancestor's repository — mirroring the repo-scoped member injection above.
	noPathMembers := s.repoOwnedNoPathMembers(typeName)
	for _, member := range noPathMembers {
		*sels = append(*sels, s.memberTypeMarkerFragment(member))
	}
	budget.count(len(noPathMembers))
}

// repoOwnedNoPathMembers returns the repo-owned-but-unattributable concrete object members of an
// interface/union (sorted), so an abstract selection that could resolve to one still gets a type
// marker and is attributed to its nearest marked ancestor by the response filter. Empty for concrete
// types and for abstract types with no such member.
func (s *Schema) repoOwnedNoPathMembers(typeName string) []string {
	def := s.schema.Types[typeName]
	if def == nil || (def.Kind != ast.Interface && def.Kind != ast.Union) {
		return nil
	}
	var out []string
	for _, pt := range s.schema.PossibleTypes[typeName] {
		if s.repoOwnedNoPath[pt.Name] {
			out = append(out, pt.Name)
		}
	}
	sort.Strings(out)
	return out
}

// memberTypeMarkerFragment builds `... on T { bghRepoTypeZ9: __typename }` for a repo-owned-no-path
// concrete type T reached through an enclosing abstract selection: T self-identifies its TYPE (so the
// filter knows its per-resource key) while the filter supplies its repository from the ancestor.
func (s *Schema) memberTypeMarkerFragment(typeName string) *ast.InlineFragment {
	return &ast.InlineFragment{
		TypeCondition: typeName,
		SelectionSet:  ast.SelectionSet{typenameMarker()},
	}
}

// repoScopedMembers returns the repo-scoped concrete object types of an interface/union, sorted
// for deterministic output. Empty for concrete types and for abstract types with no repo-scoped
// member (e.g. Actor = User|Bot|Organization), so no fragment is injected there.
func (s *Schema) repoScopedMembers(typeName string) []string {
	def := s.schema.Types[typeName]
	if def == nil || (def.Kind != ast.Interface && def.Kind != ast.Union) {
		return nil
	}
	var out []string
	for _, pt := range s.schema.PossibleTypes[typeName] {
		if s.repoScoped[pt.Name] {
			out = append(out, pt.Name)
		}
	}
	sort.Strings(out)
	return out
}

// memberMarkerFragment builds `... on T { bghRepoTagZ9: <repoPath> bghRepoTypeZ9: __typename }`
// for a repo-scoped concrete type T. T is a possible type of the enclosing abstract selection,
// so the type condition is always valid where this is injected.
func (s *Schema) memberMarkerFragment(typeName string) *ast.InlineFragment {
	return &ast.InlineFragment{
		TypeCondition: typeName,
		SelectionSet:  ast.SelectionSet{s.markerWithAlias(typeName, markerAlias+"_"+typeName), typenameMarker()},
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
	return s.markerWithAlias(typeName, markerAlias)
}

// markerWithAlias builds the repository-identifying field for a repo-scoped type under a chosen
// response key. Concrete objects use the canonical markerAlias; interface/union member fragments
// use a per-member suffixed alias so sibling fragments with differently-shaped paths (scalar
// Repository.nameWithOwner vs object X.repository{…}) don't trip GraphQL field-merge validation.
func (s *Schema) markerWithAlias(typeName, alias string) *ast.Field {
	path := s.repoPath[typeName]
	var inner ast.SelectionSet
	for i := len(path) - 1; i >= 0; i-- {
		f := &ast.Field{Name: path[i].field}
		if len(inner) > 0 {
			if path[i].onType != "" {
				// union/interface hop: narrow to `... on <onType>` before continuing the path
				f.SelectionSet = ast.SelectionSet{&ast.InlineFragment{TypeCondition: path[i].onType, SelectionSet: inner}}
			} else {
				f.SelectionSet = inner
			}
		}
		inner = ast.SelectionSet{f}
	}
	root := inner[0].(*ast.Field)
	root.Alias = alias
	return root
}

// Filter walks a GraphQL JSON response and redacts (replaces with null) any repo-scoped
// object the authorized predicate rejects, then strips the injected markers. authorized
// receives "owner", "repo", the per-resource key derived from the object's runtime __typename
// (PullRequest→"pulls", Issue→"issues", …; "metadata" for the repository container and unmapped
// types), AND the raw __typename so the caller can apply the lenient "keep the repository
// container" rule to the container ONLY, not to metadata-class CONTENT objects (Discussion/
// Milestone/Project/Tag/…) that must satisfy base access like the direct path (audit F1).
// Passing the resource lets per-resource policy (e.g. pulls="none") be enforced on objects
// reached by ANY path — navigation included — not just the entry point.
// Decision is the per-object verdict the filter's predicate returns.
type Decision int

const (
	// Deny redacts the whole object (replaced with null).
	Deny Decision = iota
	// Keep keeps the object and recurses into its children normally.
	Keep
	// KeepShell keeps a repository CONTAINER only structurally: it preserves subtrees that lead to
	// repo-scoped (marked) descendants — the granted children — but strips the container's OWN
	// data: scalar fields (description/sshUrl/diskUsage/isPrivate/…) and non-repo-scoped leaf
	// objects (contributingGuidelines.body/planFeatures/…). Used when a repo is readable in SOME
	// way (CanReadAnything) but its `metadata` resource is denied, so a `base=none` + per-resource
	// grant reached by navigation cannot leak the repo's metadata/content the direct path forbids
	// (audit F3). Only meaningful for the RepositoryContainerType; other types use Keep/Deny.
	KeepShell
)

// Filter is the bool-predicate convenience wrapper (used by tests): allowed→Keep, denied→Deny. The
// proxy uses FilterWithDecision so it can also request KeepShell for leniently-kept containers.
func Filter(resp map[string]any, authorized func(owner, repo, resource, typename string) bool) map[string]any {
	return FilterWithDecision(resp, func(owner, repo, resource, typename string) Decision {
		if authorized(owner, repo, resource, typename) {
			return Keep
		}
		return Deny
	})
}

// FilterWithDecision walks a GraphQL JSON response and applies authorize's per-object Decision to
// every repo-scoped (marked) object, then strips the injected markers.
func FilterWithDecision(resp map[string]any, authorize func(owner, repo, resource, typename string) Decision) map[string]any {
	v := filterValue(resp, authorize, "", "")
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// filterValue walks the response. ambOwner/ambRepo carry the repository of the nearest enclosing
// marked-and-kept object — the "ambient repository" used to attribute repo-owned objects that cannot
// self-identify their repo (the type-marker-only repoOwnedNoPath objects; see augment).
func filterValue(v any, authorize func(owner, repo, resource, typename string) Decision, ambOwner, ambRepo string) any {
	switch val := v.(type) {
	case map[string]any:
		childOwner, childRepo := ambOwner, ambRepo
		if tag, ok := repoMarker(val); ok {
			// A repo marker is only injected onto repo-scoped objects, so its presence means this
			// object belongs to a repository. An unparseable marker (anomalous null/malformed
			// repository) fails closed. The resource comes from the runtime type marker; absent/
			// unmapped → "metadata" (base).
			owner, repo, parsed := repoFromMarker(tag)
			typename := markerTypename(val)
			if !parsed {
				return nil
			}
			switch authorize(owner, repo, typeResource(typename), typename) {
			case Deny:
				return nil
			case KeepShell:
				stripMarkers(val)
				return shellPrune(val, authorize, owner, repo)
			default: // Keep
			}
			// A kept repo-scoped object establishes the repository context for its (possibly
			// unmarkable) descendants.
			childOwner, childRepo = owner, repo
		} else if typename := markerTypename(val); typename != "" {
			// A repo-OWNED content object with only a TYPE marker and NO repo marker (a
			// repoOwnedNoPath type: timeline events, DeploymentReview, …). It cannot self-identify
			// its repository, so attribute it to the nearest marked ancestor's repository — for these
			// types that ancestor is always the same repo — and enforce its per-resource policy there.
			// Fail closed if there is no ancestor repository to check against (round-17).
			if ambRepo == "" {
				return nil
			}
			if authorize(ambOwner, ambRepo, typeResource(typename), typename) == Deny {
				return nil
			}
		}
		stripMarkers(val) // strip injected repo + type markers (whether or not a marker rode along)
		for k, child := range val {
			val[k] = filterValue(child, authorize, childOwner, childRepo)
		}
		return val
	case []any:
		for i, child := range val {
			val[i] = filterValue(child, authorize, ambOwner, ambRepo)
		}
		return val
	default:
		return v
	}
}

// shellPrune keeps a leniently-allowed repository container as a structural shell only (see
// KeepShell). It strips every scalar field (the container's own metadata) and every child whose
// subtree contains no repo-scoped MARKED object (a non-repo-scoped leaf like contributingGuidelines),
// while recursing — via the normal filterValue, which applies each child's own Decision — into
// subtrees that DO contain marked objects (connection wrappers leading to granted issues/pulls).
func shellPrune(container map[string]any, authorize func(owner, repo, resource, typename string) Decision, ambOwner, ambRepo string) any {
	for k, child := range container {
		switch child.(type) {
		case map[string]any, []any:
			if hasMarkerDescendant(child) {
				// Granted children live here; recurse with the container's repo as the ambient
				// context so any repoOwnedNoPath descendants are attributed to this repo.
				container[k] = filterValue(child, authorize, ambOwner, ambRepo)
			} else {
				delete(container, k) // pure container-owned data (no marked object beneath)
			}
		default:
			delete(container, k) // scalar → the container's own metadata
		}
	}
	return container
}

// hasMarkerDescendant reports whether v contains, at any depth, an object carrying ANY injected
// marker — a repo marker (a repo-scoped object filterValue authorizes on its own) OR a bare type
// marker (a repoOwnedNoPath object filterValue authorizes against the ambient repo). A KeepShell
// container keeps such subtrees and prunes only its own marker-free scalars/objects.
func hasMarkerDescendant(v any) bool {
	switch val := v.(type) {
	case map[string]any:
		if _, ok := repoMarker(val); ok {
			return true
		}
		if markerTypename(val) != "" {
			return true
		}
		for _, child := range val {
			if hasMarkerDescendant(child) {
				return true
			}
		}
	case []any:
		for _, child := range val {
			if hasMarkerDescendant(child) {
				return true
			}
		}
	}
	return false
}

// RepositoryContainerType is the GraphQL __typename of the repository container object — the one
// repo-scoped type the response filter keeps leniently (whenever the repo is readable in ANY way)
// so a base=none + per-resource grant doesn't null the container and lose its granted children.
// Every OTHER repo-scoped object, including metadata-class content, must satisfy base/per-resource
// access on its own (see the filterGraphQLResponse callback in internal/proxy).
const RepositoryContainerType = "Repository"

// markerTypename returns the runtime __typename injected under markerTypeAlias, or "" if
// absent (which maps to the "metadata" resource — base access).
func markerTypename(val map[string]any) string {
	s, _ := val[markerTypeAlias].(string)
	return s
}

// repoMarker returns the repository marker injected onto an object, if any. augment keys it by
// the canonical markerAlias on a concrete repo-scoped object, or by a per-member suffixed alias
// (markerAlias+"_"+Type) when the object was selected through an interface/union; either way the
// value carries the single nameWithOwner for this object's own repository.
func repoMarker(val map[string]any) (any, bool) {
	if v, ok := val[markerAlias]; ok {
		return v, true
	}
	for k, v := range val {
		if strings.HasPrefix(k, markerAlias+"_") {
			return v, true
		}
	}
	return nil, false
}

// stripMarkers removes every injected marker (the repo marker — exact or per-member suffixed —
// and the type marker) so they never reach the client.
func stripMarkers(val map[string]any) {
	for k := range val {
		if k == markerTypeAlias || k == markerAlias || strings.HasPrefix(k, markerAlias+"_") {
			delete(val, k)
		}
	}
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

// ResourceForType returns the per-resource policy key for a GraphQL object's runtime type
// (PullRequest→"pulls", Issue→"issues", …), or "" when the type maps to no specific resource.
// The proxy uses it to derive a node-ID mutation's per-resource key from the node's REAL,
// GitHub-confirmed type rather than from the mutation field's NAME — so e.g. addComment on a
// pull request is "pulls" and on an issue is "issues", instead of the name-substring guess
// (gqlMutationResource) that returns "" for either and let the write dodge a per-resource rule.
// It is backed by the schema-derived @docsCategory map (deriveTypeResources), so coverage tracks
// the embedded schema rather than a hand-maintained list (round-15).
func (s *Schema) ResourceForType(typename string) string {
	return s.typeRes[typename] // "" when the type maps to no specific resource; caller falls back to the name guess
}

// FilterResource is the per-resource key the RESPONSE FILTER enforces on a repo-scoped object of the
// given runtime type — the same schema-derived mapping as ResourceForType, but defaulting to
// "metadata" (base access) for types with no specific resource. The proxy's response-filter callback
// uses this so per-resource policy (e.g. deployments="none") is enforced on every object whose
// @docsCategory names a real resource, not just the ~30 types an older hand map happened to list.
func (s *Schema) FilterResource(typename string) string {
	if r := s.typeRes[typename]; r != "" {
		return r
	}
	return "metadata"
}

// IsKnownNodeObjectType reports whether typename is an OBJECT type implementing Node that this
// embedded schema recognizes. The node resolver fails closed on a resolved node whose __typename is
// NOT recognized here (live schema drift), instead of treating it as a constraint-free non-repo node.
func (s *Schema) IsKnownNodeObjectType(typename string) bool {
	return s.nodeTypes[typename]
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
