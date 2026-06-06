package classifier

import (
	"bytes"
	"encoding/base64"
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
		res := Result{
			Owner:    segments[1],
			Repo:     segments[2],
			Access:   access,
			Resource: restResource(segments),
		}
		// A cross-fork compare (basehead `base...user:head`) returns the FOREIGN fork's commits/
		// file patches, which the path-repo scope does not cover and the REST response filter cannot
		// redact (the foreign content has no per-element repository identity). Add each foreign owner
		// as a scope the policy must allow, so an un-permitted fork is denied (round-16).
		res.Additional = append(res.Additional, compareForkScopes(segments)...)
		res.Additional = append(res.Additional, bodyNamedRepoScopes(method, segments, body)...)
		return res
	}

	// GitHub's Copilot coding-agent endpoints embed the repository DEEPER than segment[0]:
	// /agents/repos/{owner}/{repo}/tasks[/{task_id}]. Without this they classify to an EMPTY scope
	// (segments[0]=="agents" matches none of repos/orgs/users), which under defaults.mode="allow" is
	// allowed-by-default and falls back to the body-scan alone — and the task schema names its repo
	// only by NUMERIC id, which restfilter.ContainsDeniedRepo cannot map, so a denied repo's task
	// data leaks (round-19 F6). Scope to the path repo so a denied repo is denied regardless of mode.
	// Resource is derived over the embedded repos/{o}/{r}/… triple (a known sub-resource is gated; an
	// unknown one like "tasks" is ResourceUnknown → write-fail-closed under a per-resource rule).
	if len(segments) >= 4 && segments[0] == "agents" && segments[1] == "repos" {
		sub := segments[1:] // [repos, owner, repo, seg...]
		return Result{
			Owner:    sub[1],
			Repo:     sub[2],
			Access:   access,
			Resource: restResource(sub),
		}
	}

	if len(segments) >= 2 && segments[0] == "orgs" {
		return Result{
			Org:        segments[1],
			Access:     access,
			Resource:   orgResource(segments),
			Additional: bodyNamedRepoScopes(method, segments, body),
		}
	}

	if len(segments) >= 2 && segments[0] == "users" {
		return Result{
			Org:      segments[1],
			Access:   access,
			Resource: orgResource(segments),
		}
	}

	return Result{
		Access:           access,
		UnscopedCategory: restUnscopedCategory(segments),
		Additional:       bodyNamedRepoScopes(method, segments, body), // /user/migrations names repos in its body
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
		ids, resByID, repoScopes, ok := collectNodeIDArgs(ops, doc.Fragments, vars)
		if !ok {
			// Too complex to walk safely → no scope → unscoped write → denied.
			return Result{Access: Write}
		}
		result.NodeIDs = ids
		result.NodeIDResource = resByID
		// String-named repo targets (createCommitOnBranch's repositoryNameWithOwner) are
		// authoritative scopes the policy must allow — a carrier node must not satisfy policy while
		// the real (string-named) target goes unchecked (audit F1). When the mutation carries node
		// IDs, the proxy's resolver sets the primary scope and these are additional (all ANDed). When
		// it carries NONE, the string target IS the primary scope — otherwise the request would be an
		// empty (unscoped) write and a legitimate commit to an ALLOWED repo would be wrongly denied.
		if len(repoScopes) > 0 {
			if len(ids) == 0 {
				result.Owner = repoScopes[0].Owner
				result.Repo = repoScopes[0].Repo
				result.Resource = repoScopes[0].Resource
				result.Additional = append(result.Additional, repoScopes[1:]...)
			} else {
				result.Additional = append(result.Additional, repoScopes...)
			}
		}
		// A mutation's RETURN selection is a normal read sub-graph and can navigate to
		// other repositories (payload.pullRequest.repository.forks, ...). Scan it like a
		// read so the proxy's response filter redacts denied navigated repos when
		// available, and the request fails closed when it is not (schema drift). Without
		// this, a write grant on one repo could read any navigable repo via the payload.
		escapes := false
		navTooComplex := false
		navBudget := maxGraphQLVisits
		for _, op := range ops {
			scanCrossRepoNav(op.SelectionSet, doc.Fragments, gqlCrossRepoNavFields, &escapes, map[string]bool{}, 0, &navTooComplex, &navBudget)
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
	budget := maxGraphQLVisits
	for _, op := range ops {
		collectGraphQLScopes(op.SelectionSet, doc.Fragments, vars, add, map[string]bool{}, 0, &tooComplex, &escapes, &budget)
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
	nodeIDs, nodeRes, repoScopes, idsOk := collectNodeIDArgs(ops, doc.Fragments, vars)
	if !idsOk {
		return Result{Access: Write}
	}
	// Reads do not normally carry repositoryNameWithOwner, but include any for completeness so a
	// string-named repo a read references is policy-checked like every other scope.
	for _, s := range repoScopes {
		add(s)
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
func gqlRepoResources(repoField *ast.Field, fragments ast.FragmentDefinitionList, budget *int) []string {
	set := map[string]struct{}{}
	baseGoverned := false
	collectRepoResources(repoField.SelectionSet, fragments, set, &baseGoverned, map[string]bool{}, 0, budget)
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
func collectRepoResources(sels ast.SelectionSet, fragments ast.FragmentDefinitionList, set map[string]struct{}, baseGoverned *bool, seenFrags map[string]bool, depth int, budget *int) {
	if depth > maxGraphQLDepth {
		*baseGoverned = true
		return
	}
	for _, sel := range sels {
		if visit(budget) { // document-global visit budget (round-21)
			*baseGoverned = true
			return
		}
		switch s := sel.(type) {
		case *ast.Field:
			if r, ok := gqlFieldToResource[s.Name]; ok {
				set[r] = struct{}{}
			} else if s.Name != "__typename" {
				*baseGoverned = true // metadata or any unmapped field → rule's base access
			}
		case *ast.InlineFragment:
			collectRepoResources(s.SelectionSet, fragments, set, baseGoverned, seenFrags, depth+1, budget)
		case *ast.FragmentSpread:
			if seenFrags[s.Name] {
				continue // already expanded this fragment in this walk; re-expansion is redundant
			}
			if frag := fragments.ForName(s.Name); frag != nil {
				seenFrags[s.Name] = true
				collectRepoResources(frag.SelectionSet, fragments, set, baseGoverned, seenFrags, depth+1, budget)
			} else {
				*baseGoverned = true // unresolvable spread → can't see its fields → require base
			}
		}
	}
}

// gqlOrgFieldToResource maps an organization owner-root sub-field to the org per-resource policy key
// the REST surface gates the same data under (orgResource = the URL segment): membersWithRole/members
// → "members" (REST /orgs/{org}/members), teams/team → "teams" (REST /orgs/{org}/teams). So a
// [org.permissions] members="none" / teams="none" carve-out is enforced on the GraphQL owner-root too,
// the parity of the round-17 REST orgResource fix that the GraphQL path was missing (round-20). Only
// the member/team LIST fields an operator realistically carves out are mapped; every other org
// sub-field is base-governed (Resource ""), so plain org-metadata reads are unaffected.
var gqlOrgFieldToResource = map[string]string{
	"membersWithRole": "members",
	"members":         "members",
	"pendingMembers":  "members",
	"team":            "teams",
	"teams":           "teams",
	// Other Organization fields that enumerate MEMBER/OWNER identity (logins, and via mannequins also
	// emails / via samlIdentityProvider SAML NameIDs) — the round-20 map omitted them, so a
	// [org.permissions] members="none" carve-out the REST /orgs/{org}/members path enforces was bypassed
	// over GraphQL, leaking the member roster (mannequins additionally leaks emails the REST surface
	// never returns) — round-21. Gate them on "members" too.
	"memberStatuses":       "members",
	"mannequins":           "members",
	"enterpriseOwners":     "members",
	"samlIdentityProvider": "members",
	// The org audit log enumerates every member's login + source IP + location + per-action activity (a
	// strict SUPERSET of the roster members="none" hides). It returns OrganizationAuditEntryConnection,
	// whose AuditEntry concrete types carry actorLogin/actorIp — owner-private member identity the repo-
	// centric response filter never redacts (AuditEntry is @docsCategory "enterprise-admin"/"orgs", not a
	// repo). Unmapped it degraded to base org read, bypassing members="none" (round-22). Gate on "members".
	"auditLog": "members",
}

// gqlOrgResources returns each distinct org per-resource key an owner-root (organization/
// repositoryOwner/user) selection touches, plus "" (base org access) for any base-governed field or a
// pure-metadata selection. A query reading membersWithRole is thus gated on the "members" key; reading
// only name/description is gated on base org access exactly as before. It walks fragment boundaries
// (so `... on Organization{ membersWithRole }` under a repositoryOwner root is caught) but not into a
// field's own sub-selection, mirroring gqlRepoResources.
func gqlOrgResources(orgField *ast.Field, fragments ast.FragmentDefinitionList, budget *int) []string {
	set := map[string]struct{}{}
	baseGoverned := false
	collectOrgResources(orgField.SelectionSet, fragments, set, &baseGoverned, map[string]bool{}, 0, budget)
	out := make([]string, 0, len(set)+1)
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	if baseGoverned || len(out) == 0 {
		out = append(out, "") // base-governed/metadata fields get their own base scope (listed last)
	}
	return out
}

// collectNamedChildFields returns the direct child fields named `name` in a selection set, descending
// through inline fragments and fragment spreads (so `... on Repository { owner {…} }` and a spread are
// found) but NOT into other fields' own sub-selections. Used to reach a repository root's `owner`
// sub-selection so it can be org-scoped (round-23).
func collectNamedChildFields(sels ast.SelectionSet, fragments ast.FragmentDefinitionList, name string, seenFrags map[string]bool, depth int, budget *int) []*ast.Field {
	if depth > maxGraphQLDepth {
		return nil
	}
	var out []*ast.Field
	for _, sel := range sels {
		if visit(budget) {
			return out
		}
		switch s := sel.(type) {
		case *ast.Field:
			if s.Name == name {
				out = append(out, s)
			}
		case *ast.InlineFragment:
			out = append(out, collectNamedChildFields(s.SelectionSet, fragments, name, seenFrags, depth+1, budget)...)
		case *ast.FragmentSpread:
			if !seenFrags[s.Name] {
				seenFrags[s.Name] = true
				if frag := fragments.ForName(s.Name); frag != nil {
					out = append(out, collectNamedChildFields(frag.SelectionSet, fragments, name, seenFrags, depth+1, budget)...)
				}
			}
		}
	}
	return out
}

func collectOrgResources(sels ast.SelectionSet, fragments ast.FragmentDefinitionList, set map[string]struct{}, baseGoverned *bool, seenFrags map[string]bool, depth int, budget *int) {
	if depth > maxGraphQLDepth {
		*baseGoverned = true
		return
	}
	for _, sel := range sels {
		if visit(budget) { // document-global visit budget (round-21)
			*baseGoverned = true
			return
		}
		switch s := sel.(type) {
		case *ast.Field:
			if r, ok := gqlOrgFieldToResource[s.Name]; ok {
				set[r] = struct{}{}
			} else if s.Name != "__typename" {
				*baseGoverned = true // metadata or any unmapped field → base org access
			}
		case *ast.InlineFragment:
			collectOrgResources(s.SelectionSet, fragments, set, baseGoverned, seenFrags, depth+1, budget)
		case *ast.FragmentSpread:
			if seenFrags[s.Name] {
				continue
			}
			if frag := fragments.ForName(s.Name); frag != nil {
				seenFrags[s.Name] = true
				collectOrgResources(frag.SelectionSet, fragments, set, baseGoverned, seenFrags, depth+1, budget)
			} else {
				*baseGoverned = true // unresolvable spread → require base
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

// maxGraphQLVisits bounds the TOTAL number of selections the read-scope walk visits across ALL root
// fields of a document. The per-root walkers (gqlRepoResources/gqlOrgResources/scanCrossRepoNav) each
// use a FRESH per-root fragment-dedup map (required for correctness — a fragment spread under
// repository(A) and repository(B) contributes A's and B's scopes respectively and must be re-walked),
// so K root fields each spreading one shared fragment F is O(K·|F|) — a quadratic pre-policy CPU
// amplification under only the loose 100k-token parse cap (round-21). A document-global visit budget
// (mirroring gqlfilter's injectionBudget) collapses the worst case: once exhausted the walk fails
// closed (tooComplex → unscoped → denied). Real documents visit far fewer selections than this.
const maxGraphQLVisits = 200_000

// visit decrements the shared walk budget and reports whether it is exhausted (the caller must stop).
func visit(budget *int) bool {
	*budget--
	return *budget < 0
}

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
func scanCrossRepoNav(sels ast.SelectionSet, fragments ast.FragmentDefinitionList, fields map[string]bool, escapes *bool, seenFrags map[string]bool, depth int, tooComplex *bool, budget *int) {
	if *escapes {
		return
	}
	if depth > maxGraphQLDepth {
		*tooComplex = true
		return
	}
	for _, sel := range sels {
		if visit(budget) { // document-global visit budget (round-21)
			*tooComplex = true
			return
		}
		switch s := sel.(type) {
		case *ast.Field:
			if fields[s.Name] {
				*escapes = true
				return
			}
			scanCrossRepoNav(s.SelectionSet, fragments, fields, escapes, seenFrags, depth+1, tooComplex, budget)
		case *ast.InlineFragment:
			scanCrossRepoNav(s.SelectionSet, fragments, fields, escapes, seenFrags, depth+1, tooComplex, budget)
		case *ast.FragmentSpread:
			if seenFrags[s.Name] {
				continue // each fragment scanned once per walk: re-scan is redundant (escapes is monotonic)
			}
			if frag := fragments.ForName(s.Name); frag != nil {
				seenFrags[s.Name] = true
				scanCrossRepoNav(frag.SelectionSet, fragments, fields, escapes, seenFrags, depth+1, tooComplex, budget)
			}
		}
	}
}

// collectGraphQLScopes walks the selection set and emits a Scope for every
// repository/organization/search/unscoped target it finds — not just the first. A
// resolved repository/search field is not descended into for scope collection (its
// resource is captured by gqlRepoResource), but its subtree IS scanned for cross-repo
// navigation, which would otherwise reach repos the entry scope doesn't cover.
func collectGraphQLScopes(selections ast.SelectionSet, fragments ast.FragmentDefinitionList, vars map[string]interface{}, add func(Scope), seenFrags map[string]bool, depth int, tooComplex *bool, escapes *bool, budget *int) {
	if *tooComplex || *escapes {
		return
	}
	if depth > maxGraphQLDepth {
		*tooComplex = true
		return
	}
	for _, sel := range selections {
		if visit(budget) { // document-global visit budget bounds cross-root fragment re-walks (round-21)
			*tooComplex = true
			return
		}
		switch s := sel.(type) {
		case *ast.Field:
			switch s.Name {
			case "repository":
				owner := resolveStringArg(s.Arguments, "owner", vars)
				name := resolveStringArg(s.Arguments, "name", vars)
				if owner != "" && name != "" {
					// Emit a scope per distinct resource the selection touches so a query
					// mixing a restricted resource with a sibling can't dodge its policy.
					for _, res := range gqlRepoResources(s, fragments, budget) {
						add(Scope{Owner: owner, Repo: name, Resource: res})
					}
					// The repo's owner is reachable via `owner { ... on Organization { membersWithRole /
					// mannequins / auditLog / … } }`, returning the SAME owner-private member-identity data as
					// the organization(login:) root — but the repository root never scoped it, so a
					// [org.permissions] members="none" carve-out was bypassed on this second navigation path
					// (round-23). Scope the owner sub-selection as an org exactly as the organization root does
					// (gqlOrgResources reads gqlOrgFieldToResource), so the member-identity map gates it here too.
					for _, ownerField := range collectNamedChildFields(s.SelectionSet, fragments, "owner", map[string]bool{}, depth+1, budget) {
						for _, res := range gqlOrgResources(ownerField, fragments, budget) {
							if res != "" { // base owner-metadata stays covered by the repo's own metadata scope
								add(Scope{Org: owner, Resource: res})
							}
						}
					}
					scanCrossRepoNav(s.SelectionSet, fragments, gqlCrossRepoNavFields, escapes, map[string]bool{}, depth+1, tooComplex, budget)
					continue
				}
			case "organization", "repositoryOwner", "user":
				// owner-navigation roots: organization(login:)/repositoryOwner(login:)/user(login:)
				// all enumerate one owner's repos/orgs, so scope to that owner. user(login:) is
				// what `gh org list` uses; without this it was unscoped (denied) and a
				// user(login:){repositories} read dodged the owner scope.
				login := resolveStringArg(s.Arguments, "login", vars)
				if login != "" {
					// Emit one org scope per per-resource key the selection touches (membersWithRole →
					// "members", teams → "teams"), so a [org.permissions] carve-out is enforced over
					// GraphQL too — not just the base org access (round-20). A pure-metadata selection
					// yields a single "" (base) scope, unchanged.
					for _, res := range gqlOrgResources(s, fragments, budget) {
						add(Scope{Org: login, Resource: res})
					}
					// Enumerating this owner's own repos/orgs is allowed; reaching forks/
					// parents in other owners is not.
					scanCrossRepoNav(s.SelectionSet, fragments, gqlForkNavFields, escapes, map[string]bool{}, depth+1, tooComplex, budget)
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
				scanCrossRepoNav(s.SelectionSet, fragments, gqlCrossRepoNavFields, escapes, map[string]bool{}, depth+1, tooComplex, budget)
				continue
			case "enterprise", "enterpriseAdministratorInvitation", "enterpriseMemberInvitation":
				// Enterprise owner-private data (billingEmail/securityContactEmail/members/organizations/
				// ownerInfo + admin/member invitations) is reached only via these roots — they have no scoped
				// classifier root, so before round-21 they emitted NO scope and fell to Defaults.Mode (a
				// default=allow leak; the response filter is repo-centric and never redacts Enterprise data).
				// Scope to the enterprise slug as an org so an [[org]] rule matching the slug gates it and a
				// default-deny denies it — the navigation analogue of the round-20 owner-owned node(id:)
				// fail-closed. (EnterpriseRepositoryInfo is still redacted by its own repo marker.) The slug
				// lives under `slug` on enterprise(...) but `enterpriseSlug` on the invitation roots; the
				// *ByToken invitation roots are secret-invitation-token-gated (the token IS the auth, no
				// policy bypass) so they stay in the public allowlist (round-22).
				slug := resolveStringArg(s.Arguments, "slug", vars)
				if slug == "" {
					slug = resolveStringArg(s.Arguments, "enterpriseSlug", vars)
				}
				if slug != "" {
					add(Scope{Org: slug})
					scanCrossRepoNav(s.SelectionSet, fragments, gqlForkNavFields, escapes, map[string]bool{}, depth+1, tooComplex, budget)
				} else {
					add(Scope{UnscopedCategory: "meta"}) // no resolvable slug → deny via an unscoped category under default-deny
				}
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
				scanCrossRepoNav(s.SelectionSet, fragments, gqlCrossRepoNavFields, escapes, map[string]bool{}, depth+1, tooComplex, budget)
				continue
			}
			if len(s.SelectionSet) > 0 {
				collectGraphQLScopes(s.SelectionSet, fragments, vars, add, seenFrags, depth+1, tooComplex, escapes, budget)
			}
		case *ast.InlineFragment:
			collectGraphQLScopes(s.SelectionSet, fragments, vars, add, seenFrags, depth+1, tooComplex, escapes, budget)
		case *ast.FragmentSpread:
			if seenFrags[s.Name] {
				continue // expand each fragment once per walk: scopes are deduped, escapes monotonic
			}
			if frag := fragments.ForName(s.Name); frag != nil {
				seenFrags[s.Name] = true
				collectGraphQLScopes(frag.SelectionSet, fragments, vars, add, seenFrags, depth+1, tooComplex, escapes, budget)
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
	case ast.StringValue, ast.BlockValue:
		// BlockValue is a triple-quoted GraphQL string ("""…"""). GitHub accepts it anywhere a
		// String literal is valid, so a repository owner/name/login/search query supplied as a
		// block string must be read here too — otherwise it reaches GitHub unscoped (round-15).
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
//
// The 16-char floor on legacyNodeIDPattern would MISS short legacy IDs: a small databaseId
// encodes under 16 base64 chars (base64("05:Issue1") = "MDU6SXNzdWUx", 12 chars), so a mutation
// could ride a denied object's short legacy ID past resolution behind an allowed carrier node
// (round-19 F5). Rather than lower the floor — which would collect every 8+char owner login / ref
// as a false candidate and trigger a wasteful upstream resolve on ordinary reads —
// looksLikeShortLegacyNodeID closes the gap precisely: it base64-DECODES an 8–15 char value and
// accepts it only if it has the legacy "NN:TypeName<id>" decoded shape (leading digit + colon), so
// "facebook" (decodes to non-colon garbage) is not collected but "MDU6SXNzdWUx" is.
var (
	newNodeIDPattern    = regexp.MustCompile(`^[A-Za-z0-9]+_[A-Za-z0-9_=/+-]+$`)
	legacyNodeIDPattern = regexp.MustCompile(`^[A-Za-z0-9+/]{16,}={0,2}$`)
)

func looksLikeNodeID(s string) bool {
	return newNodeIDPattern.MatchString(s) || legacyNodeIDPattern.MatchString(s) || looksLikeShortLegacyNodeID(s)
}

// looksLikeShortLegacyNodeID catches legacy GraphQL node IDs shorter than the 16-char floor of
// legacyNodeIDPattern. Legacy IDs are base64 of "NN:TypeName<databaseId>"; a small databaseId makes
// the encoding 8–15 chars. It is intentionally narrow (a leading ASCII digit and a colon in the
// DECODED bytes) so it does not collect ordinary 8+char identifiers (owner logins, refs, cursors)
// as false node-ID candidates — over-collection is safe but wastes upstream resolve calls.
func looksLikeShortLegacyNodeID(s string) bool {
	if len(s) < 8 || len(s) >= 16 {
		return false // 16+ already handled by legacyNodeIDPattern; <8 is too short for a real legacy ID
	}
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		if dec, err = base64.RawStdEncoding.DecodeString(s); err != nil {
			return false
		}
	}
	return len(dec) >= 4 && dec[0] >= '0' && dec[0] <= '9' && bytes.IndexByte(dec, ':') > 0
}

// isExcludedNodeIDKey reports whether an argument/object-field name holds a NON-node value that
// must never be treated as a node ID: client strings (clientMutationId, externalId) and git
// object SHAs (*Oid, e.g. headRefOid, expectedHeadOid — a 40-hex SHA matches the legacy node-ID
// shape). Every OTHER key is eligible: a value is collected iff it matches looksLikeNodeID,
// regardless of whether the key ends in "id"/"ids". The previous name heuristic let a repo-scoped
// node ID ride in under a key like `inReplyTo` (AddPullRequestReviewCommentInput) — never
// collected, never resolved, never policy-checked — so a mutation could write into a denied repo's
// PR review thread (audit F1). Over-collection is safe by design: a non-node value resolves to
// null and is ignored; the dangerous direction is missing one.
func isExcludedNodeIDKey(name string) bool {
	n := strings.ToLower(name)
	return n == "clientmutationid" || n == "externalid" || strings.HasSuffix(n, "oid")
}

// collectibleNodeIDKey reports whether a value under argument/field `name` should be collected as a
// node ID. Excluded keys (clientMutationId/externalId and *Oid git-SHA fields) are skipped UNLESS the
// value has the modern "prefix_base64" node-ID shape — which a 40-hex GitObjectID never matches (it has
// no underscore) — so a genuine ID-typed argument whose name merely ends in "oid" (e.g.
// AddDiscussionCommentInput.replyToId, whose value is a DiscussionComment node ID) is still scoped
// rather than silently dropped from policy. The blind *oid suffix exclusion was a name-based fail-open;
// this narrows it to actual SHA-shaped values (round-20). add() re-filters by node-ID shape regardless.
func collectibleNodeIDKey(name, value string) bool {
	if !isExcludedNodeIDKey(name) {
		return true
	}
	return newNodeIDPattern.MatchString(value)
}

// isRepoSpecKey reports whether an input field names a repository by STRING ("owner/repo")
// rather than by node ID. GitHub's `CommittableBranch.repositoryNameWithOwner` (used by
// createCommitOnBranch) is the canonical case: the write target is a plain string the node-ID
// collector never sees, so without parsing it into an explicit scope a commit could be written
// into a fully-denied repo while a benign "carrier" node satisfied policy (audit F1, CRITICAL).
func isRepoSpecKey(name string) bool {
	return strings.EqualFold(name, "repositoryNameWithOwner")
}

// splitOwnerRepo parses an "owner/repo" string (exactly one slash, non-empty halves).
func splitOwnerRepo(s string) (owner, repo string, ok bool) {
	if strings.Count(s, "/") != 1 {
		return "", "", false
	}
	i := strings.IndexByte(s, '/')
	if i <= 0 || i >= len(s)-1 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// collectNodeIDArgs returns the node IDs a request references through arguments —
// mutation inputs (e.g. pullRequestId) and node(id:)/nodes(ids:) reads — from inline
// arguments (under id-typed argument/object-field names) and from variables (under
// id-typed keys). It collects every node-ID-shaped value regardless of type; the proxy
// resolves each to its real repository and ignores non-repo nodes. Over-collection is
// safe — every collected ID is independently resolved and policy-checked; missing one
// would be the dangerous case. ok is false if the input is too deep/cyclic to walk
// safely; the caller fails closed.
func collectNodeIDArgs(ops ast.OperationList, fragments ast.FragmentDefinitionList, vars map[string]interface{}) (ids []string, resourceByID map[string]string, repoScopes []Scope, ok bool) {
	seen := make(map[string]bool)
	resourceByID = make(map[string]string)
	scopeSeen := make(map[Scope]bool)
	var out []string
	add := func(id, resource string) {
		if id == "" || !looksLikeNodeID(id) || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
		resourceByID[id] = resource
	}
	// addScope records a STRING-named repo target (repositoryNameWithOwner) as an explicit scope
	// the policy must allow, tagged with the enclosing root mutation field's resource. This is the
	// authoritative scope for the target — no node resolution needed (the string IS the repo).
	addScope := func(owner, repo, resource string) {
		if owner == "" || repo == "" {
			return
		}
		s := Scope{Owner: owner, Repo: repo, Resource: resource}
		if scopeSeen[s] {
			return
		}
		scopeSeen[s] = true
		repoScopes = append(repoScopes, s)
	}
	tooComplex := false
	for _, op := range ops {
		// Only mutations carry per-resource writes; for a mutation the operation's direct
		// (and top-level-fragment) fields are root mutation fields whose name maps to a
		// resource. Reads pass atRoot=false so every node maps to "".
		walkSelectionArgs(op.SelectionSet, fragments, vars, add, addScope, op.Operation == ast.Mutation, "", map[string]bool{}, 0, &tooComplex)
	}
	// Variables not bound to any walked argument: collected defensively with no resource.
	walkVarsForIDs("", vars, func(id string) { add(id, "") }, addScope, 0, &tooComplex)
	if tooComplex {
		return nil, nil, nil, false
	}
	return out, resourceByID, repoScopes, true
}

// walkSelectionArgs descends the selection set collecting node-ID arguments, tagging each
// with the resource of the enclosing ROOT mutation field. It MUST traverse inline fragments
// and fragment spreads as well as plain fields: GitHub executes a mutation field reached
// through a fragment, so a node ID hidden in one
// (`mutation{ ...F } fragment F on Mutation{ closePullRequest(input:{pullRequestId:...}) }`)
// would otherwise never be resolved or policy-checked. atRoot is true while iterating root
// mutation fields (preserved across top-level fragments); a root field's name fixes the
// resource for its whole subtree. The depth bound doubles as the cyclic-fragment guard.
func walkSelectionArgs(sels ast.SelectionSet, fragments ast.FragmentDefinitionList, vars map[string]interface{}, add func(id, resource string), addScope func(owner, repo, resource string), atRoot bool, resource string, seenFrags map[string]bool, depth int, tooComplex *bool) {
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
				walkArgValue(arg.Name, arg.Value, vars, add, addScope, res, depth+1, tooComplex)
			}
			if len(s.SelectionSet) > 0 {
				walkSelectionArgs(s.SelectionSet, fragments, vars, add, addScope, false, res, seenFrags, depth+1, tooComplex)
			}
		case *ast.InlineFragment:
			walkSelectionArgs(s.SelectionSet, fragments, vars, add, addScope, atRoot, resource, seenFrags, depth+1, tooComplex)
		case *ast.FragmentSpread:
			if seenFrags[s.Name] {
				continue // expand each fragment once per walk: node IDs are deduped
			}
			if frag := fragments.ForName(s.Name); frag != nil {
				seenFrags[s.Name] = true
				walkSelectionArgs(frag.SelectionSet, fragments, vars, add, addScope, atRoot, resource, seenFrags, depth+1, tooComplex)
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

func walkArgValue(name string, v *ast.Value, vars map[string]interface{}, add func(id, resource string), addScope func(owner, repo, resource string), resource string, depth int, tooComplex *bool) {
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
	case ast.StringValue, ast.BlockValue:
		// BlockValue ("""…""") is a valid String literal to GitHub, so a node ID or
		// repositoryNameWithOwner target supplied as a block string MUST be collected here too;
		// otherwise a multi-root mutation could hide a denied write target in a block string and
		// ride a plain-string allowed sibling past policy (round-15 CRITICAL).
		if isRepoSpecKey(name) {
			if o, r, ok := splitOwnerRepo(v.Raw); ok {
				addScope(o, r, resource)
			}
		} else if collectibleNodeIDKey(name, v.Raw) {
			add(v.Raw, resource) // add() re-filters by node-ID shape
		}
	case ast.Variable:
		s, _ := vars[v.Raw].(string)
		if isRepoSpecKey(name) {
			if o, r, ok := splitOwnerRepo(s); ok {
				addScope(o, r, resource)
			}
		} else if s != "" && collectibleNodeIDKey(name, s) {
			add(s, resource)
		}
	case ast.ObjectValue:
		for _, child := range v.Children {
			walkArgValue(child.Name, child.Value, vars, add, addScope, resource, depth+1, tooComplex)
		}
	case ast.ListValue:
		for _, child := range v.Children {
			walkArgValue(name, child.Value, vars, add, addScope, resource, depth+1, tooComplex)
		}
	}
}

func walkVarsForIDs(key string, v interface{}, add func(string), addScope func(owner, repo, resource string), depth int, tooComplex *bool) {
	if *tooComplex {
		return
	}
	if depth > maxGraphQLDepth {
		*tooComplex = true
		return
	}
	switch val := v.(type) {
	case string:
		if isRepoSpecKey(key) {
			if o, r, ok := splitOwnerRepo(val); ok {
				addScope(o, r, "")
			}
		} else if collectibleNodeIDKey(key, val) {
			add(val)
		}
	case map[string]interface{}:
		for k, child := range val {
			walkVarsForIDs(k, child, add, addScope, depth+1, tooComplex)
		}
	case []interface{}:
		for _, child := range val {
			walkVarsForIDs(key, child, add, addScope, depth+1, tooComplex)
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

// compareForkScopes returns a scope for every FOREIGN-owner repository referenced in a cross-fork
// compare basehead — GET /repos/{o}/{r}/compare/{base}...{head} and the dependency-graph variant.
// GitHub's compare API accepts a `user:ref` base/head that resolves to that user's fork in the SAME
// network, returning that fork's commits[] (author identities) and files[].patch (raw source diff).
// The path-repo scope does not cover the fork, and restfilter cannot redact it (the foreign content
// carries no per-element repository identity), so without this a read of an allowed base repo leaked
// a denied fork's private content (round-16). Each foreign owner becomes a scope on `owner/{repo}`
// (the path repo name — forks share it), so the policy must allow that fork too. The path owner
// referenced as `owner:ref` is the same repo and is skipped. Best-effort on the repo name: a renamed
// fork is the rare exception and mis-naming only ever fails an ALLOWED compare closed, never opens one.
// bodyNamedRepoScopes scopes the FOREIGN repositories a REST request names in its JSON BODY (not its
// path) — the migration and CodeQL variant-analysis endpoints, whose `repositories[]` (and the variant-
// analysis `repository_owners[]`) target repos the broad custodian token, not the client, has the reach to
// act on. Without scoping them, a client with org-migration / code-scanning write but a per-repo `none`
// carve-out could name a DENIED repo and have the custodian migrate it (full archive exfiltration) or scan
// it (round-23) — the REST-body analogue of compareForkScopes (round-16) / createCommitOnBranch (round-15).
// Each named repo becomes a scope the policy must allow, so a denied target is rejected at the front gate.
func bodyNamedRepoScopes(method string, segments []string, body []byte) []Scope {
	if method != http.MethodPost || len(body) == 0 {
		return nil
	}
	var resource string
	switch {
	case len(segments) == 3 && segments[0] == "orgs" && segments[2] == "migrations":
		resource = "migrations"
	case len(segments) == 2 && segments[0] == "user" && segments[1] == "migrations":
		resource = "migrations"
	case len(segments) == 6 && segments[0] == "repos" && segments[3] == "code-scanning" &&
		segments[4] == "codeql" && segments[5] == "variant-analyses":
		resource = restResource(segments) // the repo's code-scanning resource key
	default:
		return nil
	}
	var b struct {
		Repositories     []string `json:"repositories"`
		RepositoryOwners []string `json:"repository_owners"`
	}
	if json.Unmarshal(body, &b) != nil {
		return nil // a body GitHub itself rejects (400) runs no migration/scan, so it discloses nothing
	}
	var out []Scope
	for _, full := range b.Repositories {
		if o, r, ok := splitOwnerRepo(full); ok {
			out = append(out, Scope{Owner: o, Repo: r, Resource: resource})
		}
	}
	for _, owner := range b.RepositoryOwners {
		if owner != "" {
			out = append(out, Scope{Org: owner, Resource: resource})
		}
	}
	return out
}

func compareForkScopes(segments []string) []Scope {
	if len(segments) < 4 {
		return nil
	}
	owner, repo := segments[1], segments[2]
	var basehead string
	switch {
	case segments[3] == "compare" && len(segments) >= 5:
		basehead = strings.Join(segments[4:], "/")
	case segments[3] == "dependency-graph" && len(segments) >= 6 && segments[4] == "compare":
		basehead = strings.Join(segments[5:], "/")
	default:
		return nil
	}
	seen := map[string]bool{}
	var out []Scope
	for _, side := range splitBasehead(basehead) {
		fo, fr := forkTarget(side, repo)
		if fo == "" {
			continue // bare ref → lives in the path repo, already scoped
		}
		// Skip ONLY the exact path repo. A side that names the path OWNER but a DIFFERENT repo
		// (the documented owner:repo:ref form) must still be scoped — otherwise a same-owner
		// triple-colon compare leaks a denied repo's commits/patches (round-18 C).
		if strings.EqualFold(fo, owner) && strings.EqualFold(fr, repo) {
			continue
		}
		key := strings.ToLower(fo) + "/" + strings.ToLower(fr)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Scope{Owner: fo, Repo: fr, Resource: "commits"})
	}
	return out
}

// splitBasehead splits a compare basehead into its base and head sides. GitHub uses three-dot
// ("base...head"); two-dot ("base..head") is accepted as well. A basehead with neither separator
// is treated as a single side.
func splitBasehead(basehead string) []string {
	if i := strings.Index(basehead, "..."); i >= 0 {
		return []string{basehead[:i], basehead[i+3:]}
	}
	if i := strings.Index(basehead, ".."); i >= 0 {
		return []string{basehead[:i], basehead[i+2:]}
	}
	return []string{basehead}
}

// forkTarget parses a compare basehead side into its (owner, repo). GitHub accepts three side forms:
//   - a bare ref ("main") → ("", "") — it lives in the path repo, already scoped;
//   - "owner:ref" → a same-network fork that SHARES the path repo name → (owner, pathRepo);
//   - "owner:repo:ref" → an EXPLICIT, possibly different-named repository (GitHub docs: "octocat:
//     awesome-app:main would use the main branch in the octocat/awesome-app repository").
//
// A git ref cannot contain ':', and a repo name contains neither ':' nor '/', so fields are
// colon-delimited from the left and the middle field (if slash-free) is the repo name. Before
// round-18 this returned only the owner and the caller always scoped the PATH repo name, so a
// triple-colon side naming a different repo was mis-scoped or (same owner) dropped → leak.
func forkTarget(side, pathRepo string) (owner, repo string) {
	i := strings.IndexByte(side, ':')
	if i <= 0 {
		return "", "" // bare ref → path repo
	}
	owner = side[:i]
	rest := side[i+1:]
	if j := strings.IndexByte(rest, ':'); j > 0 {
		if mid := rest[:j]; mid != "" && !strings.Contains(mid, "/") {
			return owner, mid // owner:repo:ref
		}
	}
	return owner, pathRepo // owner:ref → shares the path repo name
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

// KnownRepoResourceKeys is the set of per-resource policy keys that can actually gate a REPOSITORY
// rule — the values restResource (incl. the git-data buckets) and the GraphQL resource mapping
// produce, plus "metadata". A [repo.permissions] / --repo-perm key OUTSIDE this set never matches
// any request, so a per-resource `none` written under a misspelled key (e.g. "contnets") silently
// degrades to the rule's BASE access — a fail-open footgun. Mint paths validate against this so a
// typo is rejected, not silently accepted (round-19 D2). Derived from restResourceMap so it cannot
// drift from what the classifier emits. NOTE: org per-resource keys are open-ended (any org subpath
// segment via orgResource), so this set governs REPO rules only.
func KnownRepoResourceKeys() map[string]bool {
	out := map[string]bool{"metadata": true}
	for _, v := range restResourceMap {
		out[v] = true
	}
	return out
}

// orgResource derives the per-resource key for an /orgs/{org}/... or /users/{user}/... path so an
// [org.permissions] override is enforced on org-DIRECT subpaths too — not only on repo requests that
// fall through to the org rule (e.g. /repos/{o}/{r}/pulls). Previously the org/user branches carried
// Resource "", and policy.Evaluate's per-resource branch is skipped when resource=="", so on a READ
// the override was silently bypassed and the request fell to the rule's base access — e.g.
// `[org.permissions] members = "none"` did NOT block GET /orgs/{org}/members, and `hooks = "none"`
// did NOT block GET /orgs/{org}/hooks (round-17). (The WRITE half was already fail-closed by the
// indeterminate-resource deny.) The org/user ROOT maps to "metadata" (mirroring the repo root); a
// subpath uses its first sub-segment as the resource key, so an operator can deny any org-direct
// resource with [org.permissions] <segment> = "none". A segment with no matching permission still
// falls back to the rule's base access, exactly as repo per-resource keys do.
func orgResource(segments []string) string {
	if len(segments) < 3 {
		return "metadata"
	}
	return segments[2]
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
	// The low-level Git Data API (/repos/{o}/{r}/git/*) is bucketed by the resource its operation
	// actually touches, NOT a standalone "git" key — so a per-resource rule isn't silently narrower
	// than the operator expects (round-15). Previously the whole namespace mapped to "git", which
	// branches=none / contents=none / commits=none did not cover, so POST /git/refs (create/
	// force-push/delete a branch) and GET /git/blobs|/git/trees (raw file bytes + tree listing)
	// escaped those restrictions even though the high-level /branches and /contents paths — and the
	// GraphQL createRef/blob/tree equivalents — were correctly gated.
	if seg == "git" {
		return gitDataResource(segments)
	}
	if r, ok := restResourceMap[seg]; ok {
		return r
	}
	if restMetadataSegments[seg] {
		return "metadata"
	}
	return ResourceUnknown
}

// gitDataResource maps a /repos/{o}/{r}/git/{sub}/… path to the same per-resource key as the
// functionally-equivalent high-level surface: refs/tags → branches, blobs/trees → contents,
// commits → commits. An unrecognized git sub-resource (or a bare /git) is ResourceUnknown so a
// write fails closed under a per-resource rule rather than inheriting base access.
func gitDataResource(segments []string) string {
	if len(segments) <= 4 {
		return ResourceUnknown
	}
	switch segments[4] {
	case "refs", "ref", "matching-refs", "tags":
		return "branches"
	case "blobs", "trees":
		return "contents"
	case "commits":
		return "commits"
	default:
		return ResourceUnknown
	}
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

	// deployKeys → "keys": mirror restResourceMap (keys/deploy-keys → "keys") so the classifier scopes
	// repository(){deployKeys{…}} to the `keys` resource and a keys="none" carve-out denies the query at
	// the front gate, identical to GET /repos/{o}/{r}/keys. The response filter also redacts DeployKey
	// objects (docsCategoryResource deploy-keys→keys) as defense in depth (round-20).
	"deployKeys": "keys",
}

func gqlMutationResource(name string) string {
	// createCommitOnBranch writes AND deletes repository FILE CONTENT (its FileChanges input adds
	// FileAddition{path,contents} and FileDeletion{path}) — the GraphQL equivalent of PUT/DELETE
	// /repos/{o}/{r}/contents/{path}. Its name contains "Branch", but it must be governed by
	// `contents`, not `branches`: otherwise a branches=write/contents=none token could write
	// arbitrary files (e.g. inject a workflow, delete CODEOWNERS). round-15.
	if name == "createCommitOnBranch" {
		return "contents"
	}
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
	// approveDeployments / rejectDeployments act on a workflow run's PENDING deployments
	// (input workflowRunId: WorkflowRun) — the GraphQL equivalent of POST /repos/{o}/{r}/
	// actions/runs/{run_id}/pending_deployments, which REST classifies as "actions". They
	// contain "Deployment" so without this they would map to "deployments", letting an
	// actions="none" token un-gate a protected environment via GraphQL (round-18 E). Keep
	// them on "actions" so the REST and GraphQL surfaces enforce the same key.
	if name == "approveDeployments" || name == "rejectDeployments" {
		return "actions"
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
