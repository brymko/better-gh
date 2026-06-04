package classifier

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

type AccessLevel int

const (
	Read AccessLevel = iota
	Write
)

func (a AccessLevel) String() string {
	if a == Write {
		return "write"
	}
	return "read"
}

type Result struct {
	Owner            string
	Repo             string
	Org              string
	Access           AccessLevel
	Resource         string
	UnscopedCategory string
	// Additional holds every other scope a single request also touches. A GraphQL
	// document may select several repositories/orgs/search targets at once and
	// GitHub executes all of them, so policy must allow EVERY scope, not just the
	// primary (Owner/Repo/Org) one. Empty for REST and single-scope requests.
	Additional []Scope
	// NodeIDs are repo-scoped GraphQL node IDs referenced by a mutation (from inline
	// arguments and variables, under id-typed keys). Mutations carry no repository()
	// scope, so the proxy resolves each node ID to its real repository before
	// authorizing the write.
	NodeIDs []string
	// NodeIDResource maps each NodeID to the per-resource key of the root mutation field
	// that referenced it (mergePullRequest → "pulls", createIssue → "issues", …). The
	// proxy stamps it on that node's resolved repository scope so a multi-root mutation
	// cannot smuggle a restricted-resource write under a different field's resource. A
	// node referenced by a field that maps to no specific resource, and every read node,
	// map to "" (the proxy falls back to the request's primary resource for reads only).
	NodeIDResource map[string]string
	// NavEscapes is set on a GraphQL read whose selection navigates from a scoped entry
	// to other repositories (owner.repositories, forks, ...). The proxy's response
	// filter handles it soundly when available, else denies.
	NavEscapes bool
}

// Scope is one (repo | org | unscoped-category) target a request touches.
type Scope struct {
	Owner            string
	Repo             string
	Org              string
	Resource         string
	UnscopedCategory string
}

// AllScopes returns the primary scope followed by any Additional scopes. The proxy
// must allow all of them.
func (r *Result) AllScopes() []Scope {
	scopes := make([]Scope, 0, 1+len(r.Additional))
	scopes = append(scopes, Scope{
		Owner: r.Owner, Repo: r.Repo, Org: r.Org,
		Resource: r.Resource, UnscopedCategory: r.UnscopedCategory,
	})
	scopes = append(scopes, r.Additional...)
	return scopes
}

func (r *Result) HasRepo() bool {
	return r.Owner != "" && r.Repo != ""
}

func (r *Result) RepoFullName() string {
	if !r.HasRepo() {
		return ""
	}
	return r.Owner + "/" + r.Repo
}

func (r *Result) EffectiveOrg() string {
	if r.Org != "" {
		return r.Org
	}
	return r.Owner
}

// NormalizePath strips /api/v3 and /api/graphql prefixes so the classifier
// works identically for both GHE-mode and Unix-socket-mode requests.
func NormalizePath(path string) string {
	if strings.HasPrefix(path, "/api/v3/") {
		return path[len("/api/v3"):]
	}
	if path == "/api/v3" {
		return "/"
	}
	if path == "/api/graphql" || path == "/api/graphql/" {
		return "/graphql"
	}
	return path
}

func Classify(method, path string, body []byte) Result {
	norm := NormalizePath(path)

	if norm == "/graphql" || norm == "/graphql/" {
		return classifyGraphQL(body)
	}

	access := Read
	if method != http.MethodGet && method != http.MethodHead {
		access = Write
	}

	segments := splitPath(norm)

	if len(segments) >= 3 && segments[0] == "repos" {
		return Result{
			Owner:    segments[1],
			Repo:     segments[2],
			Access:   access,
			Resource: restResource(segments),
		}
	}

	if len(segments) >= 2 && segments[0] == "orgs" {
		return Result{
			Org:    segments[1],
			Access: access,
		}
	}

	if len(segments) >= 2 && segments[0] == "users" {
		return Result{
			Org:    segments[1],
			Access: access,
		}
	}

	return Result{
		Access:           access,
		UnscopedCategory: restUnscopedCategory(segments),
	}
}

func classifyGraphQL(body []byte) Result {
	if len(body) == 0 {
		return Result{Access: Write}
	}

	var req struct {
		Query         string                 `json:"query"`
		Variables     map[string]interface{} `json:"variables"`
		OperationName string                 `json:"operationName"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return Result{Access: Write}
	}

	// Token-bound the PARSE itself, not just the post-parse AST walk. parser.ParseQuery uses an
	// UNLIMITED token limit and gqlparser's recursive-descent parser has no depth guard, so a
	// deeply nested query (one '{' per recursion frame, well under the 10MB body cap) overflows
	// the goroutine stack — a fatal, unrecoverable crash that fires here BEFORE any policy check.
	// ParseQueryWithTokenLimit makes the parser fail closed (p.err set, recursion unwinds) at a
	// bounded depth; the limit error is treated like any unparseable query → unscoped write → deny.
	doc, gqlErr := parser.ParseQueryWithTokenLimit(&ast.Source{Input: req.Query}, maxGraphQLTokens)
	if gqlErr != nil {
		return Result{Access: Write}
	}

	ops := selectedOperations(doc.Operations, req.OperationName)

	// GitHub substitutes a variable's DEFAULT value when the request supplies none, so
	// repository(owner:$o,name:$n) / pullRequestId:$id with defaults reach a repo the
	// classifier must still scope. Overlay defaults onto the provided variables (provided
	// values win) before any scope/node-ID extraction, or a default-supplied scope is
	// invisible to policy.
	vars := effectiveVariables(ops, req.Variables)

	// Write if any selected operation is a mutation (fail closed).
	access := Read
	var mutationFieldName string
	for _, op := range ops {
		if op.Operation == ast.Mutation {
			access = Write
			if mutationFieldName == "" {
				for _, sel := range op.SelectionSet {
					if f, ok := sel.(*ast.Field); ok && !isScopeField(f.Name) {
						mutationFieldName = f.Name
						break
					}
				}
			}
		}
	}

	if access == Write {
		result := Result{Access: Write}
		if mutationFieldName != "" {
			result.Resource = gqlMutationResource(mutationFieldName)
		}
		ids, resByID, ok := collectNodeIDArgs(ops, doc.Fragments, vars)
		if !ok {
			// Too complex to walk safely → no scope → unscoped write → denied.
			return Result{Access: Write}
		}
		result.NodeIDs = ids
		result.NodeIDResource = resByID
		// A mutation's RETURN selection is a normal read sub-graph and can navigate to
		// other repositories (payload.pullRequest.repository.forks, ...). Scan it like a
		// read so the proxy's response filter redacts denied navigated repos when
		// available, and the request fails closed when it is not (schema drift). Without
		// this, a write grant on one repo could read any navigable repo via the payload.
		escapes := false
		navTooComplex := false
		for _, op := range ops {
			scanCrossRepoNav(op.SelectionSet, doc.Fragments, gqlCrossRepoNavFields, &escapes, 0, &navTooComplex)
		}
		if navTooComplex {
			return Result{Access: Write}
		}
		result.NavEscapes = escapes
		return result
	}

	// Read: collect EVERY scope the selected operations touch — GitHub executes all
	// root fields, so every repository/org/search/unscoped target must pass policy.
	var scopes []Scope
	seen := make(map[Scope]bool)
	add := func(s Scope) {
		if s == (Scope{}) || seen[s] {
			return
		}
		seen[s] = true
		scopes = append(scopes, s)
	}
	tooComplex := false
	escapes := false
	for _, op := range ops {
		collectGraphQLScopes(op.SelectionSet, doc.Fragments, vars, add, 0, &tooComplex, &escapes)
	}
	if tooComplex {
		// A query too deep/cyclic to fully walk could hide a denied scope past the
		// recursion bound. Fail closed by treating it like an unparseable query.
		return Result{Access: Write}
	}

	// Reads can also address objects by opaque node ID (node(id:)/nodes(ids:)). Those
	// carry no repository() scope, so the proxy resolves each to its real repository
	// before allowing the read — otherwise a node-ID read would bypass a repo block
	// under default=allow.
	nodeIDs, nodeRes, idsOk := collectNodeIDArgs(ops, doc.Fragments, vars)
	if !idsOk {
		return Result{Access: Write}
	}

	// escapes marks cross-repo field navigation. The proxy's response filter handles it
	// soundly when available; otherwise it falls back to denying the request.
	var result Result
	if len(scopes) == 0 {
		if len(nodeIDs) > 0 {
			result = Result{Access: Read, NodeIDs: nodeIDs}
		} else {
			result = Result{Access: Read, UnscopedCategory: gqlUnscopedCategory(doc)}
		}
	} else {
		primary := scopes[0]
		result = Result{
			Access:           Read,
			Owner:            primary.Owner,
			Repo:             primary.Repo,
			Org:              primary.Org,
			Resource:         primary.Resource,
			UnscopedCategory: primary.UnscopedCategory,
			NodeIDs:          nodeIDs,
			Additional:       scopes[1:],
		}
	}
	result.NavEscapes = escapes
	result.NodeIDResource = nodeRes
	return result
}

// selectedOperations returns the operations a request actually executes. When an
// operationName is given, GitHub runs only that operation; otherwise (single op, or
// the spec-invalid multi-op-without-name case) we classify every operation, which
// can only add scopes and therefore only add denials.
func selectedOperations(ops ast.OperationList, name string) ast.OperationList {
	if name == "" {
		return ops
	}
	for _, op := range ops {
		if op.Name == name {
			return ast.OperationList{op}
		}
	}
	return ops
}

func isScopeField(name string) bool {
	switch name {
	case "repository", "organization", "repositoryOwner", "search", "viewer":
		return true
	}
	return false
}

// gqlRepoResources returns EVERY distinct per-resource key a repository() selection
// touches (pullRequests → "pulls", issues → "issues", object → "contents", …). Each
// becomes its own scope so the policy must allow all of them.
//
// The previous version collapsed a selection touching more than one resource — or a
// resource alongside any non-metadata field — to a single "" ("ambiguous") resource, and
// the policy engine treats "" as "use the rule's BASE access". That let a query mix a
// restricted resource with a harmless sibling to dodge a per-resource rule, e.g.
// `repository(){ pullRequests{…} issues{…} }` or `repository(){ pullRequests{…}
// viewerPermission }` slipped past `pulls = "none"`. It also only inspected DIRECT
// *ast.Field children, so wrapping the resource in a fragment
// (`repository(){ ...on Repository{ pullRequests } }`) hid it the same way. This walks
// through inline-fragment / fragment-spread boundaries (but NOT into a field's own
// sub-selection) and emits each resource it finds.
//
// Fields that map to no resource (metadata, unmapped fields) add a "metadata" scope so
// the rule's base access still governs them; __typename never contributes. A selection
// with no resource fields yields just "metadata" (unchanged behaviour).
func gqlRepoResources(repoField *ast.Field, fragments ast.FragmentDefinitionList) []string {
	set := map[string]struct{}{}
	baseGoverned := false
	collectRepoResources(repoField.SelectionSet, fragments, set, &baseGoverned, 0)
	if len(set) == 0 {
		return []string{"metadata"}
	}
	out := make([]string, 0, len(set)+1)
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out) // deterministic; a real resource stays the primary (audit) scope
	if baseGoverned {
		out = append(out, "metadata") // base-governed fields get their own scope, listed last
	}
	return out
}

// collectRepoResources flattens the repository selection across fragment boundaries to
// find the per-resource keys of its direct fields. It does NOT descend into a field's own
// sub-selection (a resource is fixed by the repository's direct child, not by fields
// nested under it). The depth bound is the cyclic-fragment guard; on exceed it sets
// baseGoverned (require the rule's base access) and stops — fail closed, never silently
// drop a resource.
func collectRepoResources(sels ast.SelectionSet, fragments ast.FragmentDefinitionList, set map[string]struct{}, baseGoverned *bool, depth int) {
	if depth > maxGraphQLDepth {
		*baseGoverned = true
		return
	}
	for _, sel := range sels {
		switch s := sel.(type) {
		case *ast.Field:
			if r, ok := gqlFieldToResource[s.Name]; ok {
				set[r] = struct{}{}
			} else if s.Name != "__typename" {
				*baseGoverned = true // metadata or any unmapped field → rule's base access
			}
		case *ast.InlineFragment:
			collectRepoResources(s.SelectionSet, fragments, set, baseGoverned, depth+1)
		case *ast.FragmentSpread:
			if frag := fragments.ForName(s.Name); frag != nil {
				collectRepoResources(frag.SelectionSet, fragments, set, baseGoverned, depth+1)
			} else {
				*baseGoverned = true // unresolvable spread → can't see its fields → require base
			}
		}
	}
}

func gqlUnscopedCategory(doc *ast.QueryDocument) string {
	for _, op := range doc.Operations {
		for _, sel := range op.SelectionSet {
			f, ok := sel.(*ast.Field)
			if !ok {
				continue
			}
			switch f.Name {
			case "viewer":
				return "user"
			case "search":
				return "search"
			case "rateLimit", "__schema", "__type", "__typename":
				return "meta"
			}
		}
	}
	return ""
}

// maxGraphQLDepth bounds recursion over the parsed GraphQL AST. parser.ParseQuery does
// not validate fragment cycles or limit nesting, so an unbounded recursive walk would
// stack-overflow (an unrecoverable crash) on a crafted query — cyclic fragments, long
// fragment chains, or deeply nested selections. Legitimate queries are far shallower
// than this bound; exceeding it sets *tooComplex and the caller fails closed.
const maxGraphQLDepth = 200

// maxGraphQLTokens bounds the gqlparser token count so the recursive-descent PARSE cannot
// stack-overflow before the AST exists (see classifyGraphQL). Each nesting level costs at least
// two tokens (a field name + '{'), so this caps parse recursion near ~50k levels — orders of
// magnitude below the ~500k-deep crash threshold, yet far above any real query (the largest
// legitimate `gh`/`gh api graphql` documents are a few thousand tokens). A query exceeding it
// fails closed (denied), the same as an unparseable one.
const maxGraphQLTokens = 100_000

// gqlCrossRepoNavFields are fields that navigate from one repository/object to a
// DIFFERENT repository. GitHub executes them and the proxy streams the response
// unfiltered, so when any appears inside a scoped repository()/node()/search selection
// the classifier cannot bound which repos the response touches — it fails closed.
var gqlCrossRepoNavFields = map[string]bool{
	"repositories":       true, // owner.repositories — enumerate all of an owner's repos
	"repository":         true, // owner.repository(name:) — navigate to a named repo
	"forks":              true,
	"parent":             true,
	"source":             true, // fork source / cross-referenced object
	"templateRepository": true,
	"headRepository":     true,
	"baseRepository":     true,
}

// gqlForkNavFields is the subset used inside an organization/owner scope, where
// enumerating that owner's own repositories is legitimate (the policy granted org/owner
// access) but navigating to forks/parents in OTHER owners still escapes the scope.
var gqlForkNavFields = map[string]bool{
	"forks":              true,
	"parent":             true,
	"source":             true,
	"templateRepository": true,
	"headRepository":     true,
	"baseRepository":     true,
}

// scanCrossRepoNav reports (via *escapes) whether a selection subtree navigates to a
// repository outside the entry scope, using the given field denylist. It is run on the
// children of a resolved scope, which are otherwise not policy-checked.
func scanCrossRepoNav(sels ast.SelectionSet, fragments ast.FragmentDefinitionList, fields map[string]bool, escapes *bool, depth int, tooComplex *bool) {
	if *escapes {
		return
	}
	if depth > maxGraphQLDepth {
		*tooComplex = true
		return
	}
	for _, sel := range sels {
		switch s := sel.(type) {
		case *ast.Field:
			if fields[s.Name] {
				*escapes = true
				return
			}
			scanCrossRepoNav(s.SelectionSet, fragments, fields, escapes, depth+1, tooComplex)
		case *ast.InlineFragment:
			scanCrossRepoNav(s.SelectionSet, fragments, fields, escapes, depth+1, tooComplex)
		case *ast.FragmentSpread:
			if frag := fragments.ForName(s.Name); frag != nil {
				scanCrossRepoNav(frag.SelectionSet, fragments, fields, escapes, depth+1, tooComplex)
			}
		}
	}
}

// collectGraphQLScopes walks the selection set and emits a Scope for every
// repository/organization/search/unscoped target it finds — not just the first. A
// resolved repository/search field is not descended into for scope collection (its
// resource is captured by gqlRepoResource), but its subtree IS scanned for cross-repo
// navigation, which would otherwise reach repos the entry scope doesn't cover.
func collectGraphQLScopes(selections ast.SelectionSet, fragments ast.FragmentDefinitionList, vars map[string]interface{}, add func(Scope), depth int, tooComplex *bool, escapes *bool) {
	if *tooComplex || *escapes {
		return
	}
	if depth > maxGraphQLDepth {
		*tooComplex = true
		return
	}
	for _, sel := range selections {
		switch s := sel.(type) {
		case *ast.Field:
			switch s.Name {
			case "repository":
				owner := resolveStringArg(s.Arguments, "owner", vars)
				name := resolveStringArg(s.Arguments, "name", vars)
				if owner != "" && name != "" {
					// Emit a scope per distinct resource the selection touches so a query
					// mixing a restricted resource with a sibling can't dodge its policy.
					for _, res := range gqlRepoResources(s, fragments) {
						add(Scope{Owner: owner, Repo: name, Resource: res})
					}
					scanCrossRepoNav(s.SelectionSet, fragments, gqlCrossRepoNavFields, escapes, depth+1, tooComplex)
					continue
				}
			case "organization", "repositoryOwner", "user":
				// owner-navigation roots: organization(login:)/repositoryOwner(login:)/user(login:)
				// all enumerate one owner's repos/orgs, so scope to that owner. user(login:) is
				// what `gh org list` uses; without this it was unscoped (denied) and a
				// user(login:){repositories} read dodged the owner scope.
				login := resolveStringArg(s.Arguments, "login", vars)
				if login != "" {
					add(Scope{Org: login})
					// Enumerating this owner's own repos/orgs is allowed; reaching forks/
					// parents in other owners is not.
					scanCrossRepoNav(s.SelectionSet, fragments, gqlForkNavFields, escapes, depth+1, tooComplex)
					continue
				}
			case "search":
				query := resolveStringArg(s.Arguments, "query", vars)
				repos := parseSearchRepoQualifiers(query)
				if len(repos) > 0 {
					for _, rp := range repos {
						add(Scope{Owner: rp.owner, Repo: rp.repo})
					}
				} else {
					add(Scope{UnscopedCategory: "search"})
				}
				// Result nodes can navigate off to other repos just like repository().
				scanCrossRepoNav(s.SelectionSet, fragments, gqlCrossRepoNavFields, escapes, depth+1, tooComplex)
				continue
			case "viewer":
				add(Scope{UnscopedCategory: "user"})
				continue
			case "rateLimit":
				add(Scope{UnscopedCategory: "meta"})
				continue
			case "__schema", "__type", "__typename":
				// Schema introspection — public GraphQL metadata, no repo/user data. gh runs an
				// introspection query (e.g. to discover Repository's fields before `gh repo
				// list`) so classify it as "meta" (which minted tokens always get) not deny.
				add(Scope{UnscopedCategory: "meta"})
				continue
			case "node", "nodes":
				// Addressed by node ID (resolved + policy-checked by the proxy); scan
				// the selection so navigation off the node also fails closed.
				scanCrossRepoNav(s.SelectionSet, fragments, gqlCrossRepoNavFields, escapes, depth+1, tooComplex)
				continue
			}
			if len(s.SelectionSet) > 0 {
				collectGraphQLScopes(s.SelectionSet, fragments, vars, add, depth+1, tooComplex, escapes)
			}
		case *ast.InlineFragment:
			collectGraphQLScopes(s.SelectionSet, fragments, vars, add, depth+1, tooComplex, escapes)
		case *ast.FragmentSpread:
			if frag := fragments.ForName(s.Name); frag != nil {
				collectGraphQLScopes(frag.SelectionSet, fragments, vars, add, depth+1, tooComplex, escapes)
			}
		}
	}
}

func resolveStringArg(args ast.ArgumentList, name string, vars map[string]interface{}) string {
	arg := args.ForName(name)
	if arg == nil {
		return ""
	}
	switch arg.Value.Kind {
	case ast.Variable:
		v, _ := vars[arg.Value.Raw].(string)
		return v
	case ast.StringValue:
		return arg.Value.Raw
	}
	return ""
}

// node ID shapes the classifier extracts. GitHub uses two forms: the modern
// "prefix_base64url" (PR_kwDO..., CR_..., U_kgDO...) and legacy base64 of "NN:TypeNN"
// (e.g. MDEwOlJlcG9zaXRvcnkx...). Both are matched so older objects aren't missed.
//
// The classifier extracts EVERY id-typed value matching either shape and does NOT decide
// repo-vs-non-repo here — that requires authoritative resolution. The proxy resolves each
// to its real repository, so repo-scoped types are checked regardless of prefix or ID era
// (no allowlist to fall behind). Over-extraction is harmless: a value that does not
// resolve to a node is ignored by the resolver. The key exclusions and the minimum length
// only avoid wasted resolve calls on obvious non-IDs (commit OIDs, client strings).
var (
	newNodeIDPattern    = regexp.MustCompile(`^[A-Za-z0-9]+_[A-Za-z0-9_=/+-]+$`)
	legacyNodeIDPattern = regexp.MustCompile(`^[A-Za-z0-9+/]{16,}={0,2}$`)
)

func looksLikeNodeID(s string) bool {
	return newNodeIDPattern.MatchString(s) || legacyNodeIDPattern.MatchString(s)
}

// isNodeIDArgKey reports whether an argument/field name carries a node ID. It excludes
// id-suffixed keys that hold non-node values: client strings (clientMutationId,
// externalId) and git object SHAs (*Oid, e.g. headRefOid, expectedHeadOid).
func isNodeIDArgKey(name string) bool {
	n := strings.ToLower(name)
	if n == "clientmutationid" || n == "externalid" || strings.HasSuffix(n, "oid") {
		return false
	}
	return strings.HasSuffix(n, "id") || strings.HasSuffix(n, "ids")
}

// collectNodeIDArgs returns the node IDs a request references through arguments —
// mutation inputs (e.g. pullRequestId) and node(id:)/nodes(ids:) reads — from inline
// arguments (under id-typed argument/object-field names) and from variables (under
// id-typed keys). It collects every node-ID-shaped value regardless of type; the proxy
// resolves each to its real repository and ignores non-repo nodes. Over-collection is
// safe — every collected ID is independently resolved and policy-checked; missing one
// would be the dangerous case. ok is false if the input is too deep/cyclic to walk
// safely; the caller fails closed.
func collectNodeIDArgs(ops ast.OperationList, fragments ast.FragmentDefinitionList, vars map[string]interface{}) (ids []string, resourceByID map[string]string, ok bool) {
	seen := make(map[string]bool)
	resourceByID = make(map[string]string)
	var out []string
	add := func(id, resource string) {
		if id == "" || !looksLikeNodeID(id) || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
		resourceByID[id] = resource
	}
	tooComplex := false
	for _, op := range ops {
		// Only mutations carry per-resource writes; for a mutation the operation's direct
		// (and top-level-fragment) fields are root mutation fields whose name maps to a
		// resource. Reads pass atRoot=false so every node maps to "".
		walkSelectionArgs(op.SelectionSet, fragments, vars, add, op.Operation == ast.Mutation, "", 0, &tooComplex)
	}
	// Variables not bound to any walked argument: collected defensively with no resource.
	walkVarsForIDs("", vars, func(id string) { add(id, "") }, 0, &tooComplex)
	if tooComplex {
		return nil, nil, false
	}
	return out, resourceByID, true
}

// walkSelectionArgs descends the selection set collecting node-ID arguments, tagging each
// with the resource of the enclosing ROOT mutation field. It MUST traverse inline fragments
// and fragment spreads as well as plain fields: GitHub executes a mutation field reached
// through a fragment, so a node ID hidden in one
// (`mutation{ ...F } fragment F on Mutation{ closePullRequest(input:{pullRequestId:...}) }`)
// would otherwise never be resolved or policy-checked. atRoot is true while iterating root
// mutation fields (preserved across top-level fragments); a root field's name fixes the
// resource for its whole subtree. The depth bound doubles as the cyclic-fragment guard.
func walkSelectionArgs(sels ast.SelectionSet, fragments ast.FragmentDefinitionList, vars map[string]interface{}, add func(id, resource string), atRoot bool, resource string, depth int, tooComplex *bool) {
	if *tooComplex {
		return
	}
	if depth > maxGraphQLDepth {
		*tooComplex = true
		return
	}
	for _, sel := range sels {
		switch s := sel.(type) {
		case *ast.Field:
			res := resource
			if atRoot {
				res = gqlMutationResource(s.Name)
			}
			for _, arg := range s.Arguments {
				walkArgValue(arg.Name, arg.Value, vars, add, res, depth+1, tooComplex)
			}
			if len(s.SelectionSet) > 0 {
				walkSelectionArgs(s.SelectionSet, fragments, vars, add, false, res, depth+1, tooComplex)
			}
		case *ast.InlineFragment:
			walkSelectionArgs(s.SelectionSet, fragments, vars, add, atRoot, resource, depth+1, tooComplex)
		case *ast.FragmentSpread:
			if frag := fragments.ForName(s.Name); frag != nil {
				walkSelectionArgs(frag.SelectionSet, fragments, vars, add, atRoot, resource, depth+1, tooComplex)
			}
		}
	}
}

// effectiveVariables overlays each selected operation's variable DEFAULT values onto the
// request-supplied variables (a provided value always wins). GitHub applies defaults when
// a variable is omitted, so scope/node-ID extraction must see them too — otherwise a
// default-supplied repository() owner/name or mutation node ID is invisible to policy.
func effectiveVariables(ops ast.OperationList, provided map[string]interface{}) map[string]interface{} {
	eff := make(map[string]interface{}, len(provided))
	for k, v := range provided {
		eff[k] = v
	}
	for _, op := range ops {
		for _, vd := range op.VariableDefinitions {
			if vd.DefaultValue == nil {
				continue
			}
			if _, ok := eff[vd.Variable]; ok {
				continue
			}
			if val, err := vd.DefaultValue.Value(nil); err == nil && val != nil {
				eff[vd.Variable] = val
			}
		}
	}
	return eff
}

func walkArgValue(name string, v *ast.Value, vars map[string]interface{}, add func(id, resource string), resource string, depth int, tooComplex *bool) {
	if *tooComplex {
		return
	}
	if depth > maxGraphQLDepth {
		*tooComplex = true
		return
	}
	if v == nil {
		return
	}
	switch v.Kind {
	case ast.StringValue:
		if isNodeIDArgKey(name) {
			add(v.Raw, resource)
		}
	case ast.Variable:
		if isNodeIDArgKey(name) {
			if s, ok := vars[v.Raw].(string); ok {
				add(s, resource)
			}
		}
	case ast.ObjectValue:
		for _, child := range v.Children {
			walkArgValue(child.Name, child.Value, vars, add, resource, depth+1, tooComplex)
		}
	case ast.ListValue:
		for _, child := range v.Children {
			walkArgValue(name, child.Value, vars, add, resource, depth+1, tooComplex)
		}
	}
}

func walkVarsForIDs(key string, v interface{}, add func(string), depth int, tooComplex *bool) {
	if *tooComplex {
		return
	}
	if depth > maxGraphQLDepth {
		*tooComplex = true
		return
	}
	switch val := v.(type) {
	case string:
		if isNodeIDArgKey(key) {
			add(val)
		}
	case map[string]interface{}:
		for k, child := range val {
			walkVarsForIDs(k, child, add, depth+1, tooComplex)
		}
	case []interface{}:
		for _, child := range val {
			walkVarsForIDs(key, child, add, depth+1, tooComplex)
		}
	}
}

type ownerRepo struct{ owner, repo string }

// parseSearchRepoQualifiers returns EVERY repo: qualifier in a search query. GitHub
// search treats multiple repo: qualifiers as a union, so each is a scope that must
// pass policy — returning only the first would let a denied repo ride along.
func parseSearchRepoQualifiers(query string) []ownerRepo {
	var out []ownerRepo
	for _, part := range strings.Fields(query) {
		if strings.HasPrefix(part, "repo:") {
			spec := part[len("repo:"):]
			if slash := strings.IndexByte(spec, '/'); slash > 0 && slash < len(spec)-1 {
				out = append(out, ownerRepo{owner: spec[:slash], repo: spec[slash+1:]})
			}
		}
	}
	return out
}

var restResourceMap = map[string]string{
	"pulls":        "pulls",
	"issues":       "issues",
	"contents":     "contents",
	"readme":       "contents",
	"zipball":      "contents",
	"tarball":      "contents",
	"actions":      "actions",
	"releases":     "releases",
	"git":          "git",
	"commits":      "commits",
	"compare":      "commits",
	"branches":     "branches",
	"check-runs":   "checks",
	"check-suites": "checks",
	"statuses":     "checks",
	"comments":     "comments",
	"hooks":        "hooks",
	"deployments":  "deployments",
	"environments": "deployments",
	"pages":        "pages",
	"keys":         "keys",
	"deploy-keys":  "keys",
}

var restMetadataSegments = map[string]bool{
	"stargazers": true, "subscribers": true, "topics": true,
	"languages": true, "tags": true, "forks": true,
	"contributors": true, "collaborators": true, "teams": true,
	"license": true, "community": true, "traffic": true,
}

// ResourceUnknown marks a repo sub-resource the classifier does not recognize. It is
// distinct from "" (no resource determinable, e.g. ambiguous GraphQL): the policy
// engine refuses to let an unknown WRITE inherit a rule's base grant when per-resource
// permissions are in effect, so a per-resource 'none' cannot be dodged via an unmapped
// sibling endpoint (e.g. POST /repos/o/r/dispatches escaping actions=none).
const ResourceUnknown = "unknown"

func restResource(segments []string) string {
	if len(segments) <= 3 {
		return "metadata"
	}
	seg := segments[3]
	if r, ok := restResourceMap[seg]; ok {
		return r
	}
	if restMetadataSegments[seg] {
		return "metadata"
	}
	return ResourceUnknown
}

var restUnscopedMap = map[string]string{
	"user":          "user",
	"search":        "search",
	"gists":         "gists",
	"notifications": "notifications",
	"events":        "events",
	"rate_limit":    "meta",
	"feeds":         "meta",
	"meta":          "meta",
	"octocat":       "meta",
	"zen":           "meta",
	"emojis":        "meta",
}

func restUnscopedCategory(segments []string) string {
	if len(segments) == 0 {
		return "meta"
	}
	if c, ok := restUnscopedMap[segments[0]]; ok {
		return c
	}
	return ""
}

var gqlFieldToResource = map[string]string{
	"pullRequest":  "pulls",
	"pullRequests": "pulls",

	"issue":        "issues",
	"issues":       "issues",
	"pinnedIssues": "issues",

	"object": "contents",
	"blob":   "contents",
	"tree":   "contents",

	"refs":             "branches",
	"ref":              "branches",
	"defaultBranchRef": "branches",

	"releases":      "releases",
	"release":       "releases",
	"latestRelease": "releases",

	"commit":         "commits",
	"commitComments": "commits",

	"deployments": "deployments",
}

func gqlMutationResource(name string) string {
	if strings.Contains(name, "PullRequest") ||
		name == "enablePullRequestAutoMerge" ||
		name == "disablePullRequestAutoMerge" {
		return "pulls"
	}
	if strings.Contains(name, "Issue") {
		return "issues"
	}
	// mergeBranch advances a branch tip (a merge commit on the base branch), so it is a
	// branches write — NOT pulls. It contains "Branch", so it maps here. (Previously it was
	// special-cased to "pulls", letting it escape a branches="none" rule under pulls=write.)
	if strings.Contains(name, "Ref") || strings.Contains(name, "Branch") {
		return "branches"
	}
	if strings.Contains(name, "Release") {
		return "releases"
	}
	if strings.Contains(name, "Deployment") {
		return "deployments"
	}
	if strings.Contains(name, "Check") {
		return "checks"
	}
	return ""
}

func splitPath(path string) []string {
	var segments []string
	for _, s := range strings.Split(path, "/") {
		if s != "" {
			segments = append(segments, s)
		}
	}
	return segments
}

// HasDotSegment reports whether the path contains a "." or ".." segment. Such a
// path is classified from the segments before the "..", but the proxy forwards the
// ".." verbatim to GitHub — if GitHub's edge collapses it, the request reaches a
// different resource than the one policy checked. (Percent-encoded slashes decode
// into the path before this runs, so this also catches %2F-smuggled traversal.)
// Legitimate GitHub REST paths never contain dot segments, so the proxy rejects them.
func HasDotSegment(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// IsGHEAuthEndpoint returns true for paths that gh uses during auth
// and that should bypass policy (they don't access repo data).
func IsGHEAuthEndpoint(method, path string) bool {
	norm := NormalizePath(path)
	if norm == "/" || norm == "" {
		return method == http.MethodGet
	}
	return false
}
