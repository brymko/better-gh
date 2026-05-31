package classifier

import (
	"encoding/json"
	"net/http"
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

	doc, gqlErr := parser.ParseQuery(&ast.Source{Input: req.Query})
	if gqlErr != nil {
		return Result{Access: Write}
	}

	ops := selectedOperations(doc.Operations, req.OperationName)

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
		result.NodeIDs = collectMutationNodeIDs(ops, req.Variables)
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
	for _, op := range ops {
		collectGraphQLScopes(op.SelectionSet, doc.Fragments, req.Variables, add)
	}

	if len(scopes) == 0 {
		return Result{Access: Read, UnscopedCategory: gqlUnscopedCategory(doc)}
	}

	primary := scopes[0]
	return Result{
		Access:           Read,
		Owner:            primary.Owner,
		Repo:             primary.Repo,
		Org:              primary.Org,
		Resource:         primary.Resource,
		UnscopedCategory: primary.UnscopedCategory,
		Additional:       scopes[1:],
	}
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

func gqlRepoResource(repoField *ast.Field) string {
	found := ""
	for _, sel := range repoField.SelectionSet {
		f, ok := sel.(*ast.Field)
		if !ok {
			continue
		}
		if r, ok := gqlFieldToResource[f.Name]; ok {
			if found != "" && found != r {
				return ""
			}
			found = r
		} else if !gqlMetadataFields[f.Name] && f.Name != "__typename" {
			if found != "" && found != "metadata" {
				return ""
			}
		}
	}
	if found == "" {
		return "metadata"
	}
	return found
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
			case "rateLimit":
				return "meta"
			}
		}
	}
	return ""
}

// collectGraphQLScopes walks the selection set and emits a Scope for every
// repository/organization/search/unscoped target it finds — not just the first.
// A resolved repository/search field is not descended into: its own resource is
// captured by gqlRepoResource, and cross-referenced foreign objects beneath it
// must not be mistaken for additional top-level targets.
func collectGraphQLScopes(selections ast.SelectionSet, fragments ast.FragmentDefinitionList, vars map[string]interface{}, add func(Scope)) {
	for _, sel := range selections {
		switch s := sel.(type) {
		case *ast.Field:
			switch s.Name {
			case "repository":
				owner := resolveStringArg(s.Arguments, "owner", vars)
				name := resolveStringArg(s.Arguments, "name", vars)
				if owner != "" && name != "" {
					add(Scope{Owner: owner, Repo: name, Resource: gqlRepoResource(s)})
					continue
				}
			case "organization", "repositoryOwner":
				login := resolveStringArg(s.Arguments, "login", vars)
				if login != "" {
					add(Scope{Org: login})
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
				continue
			case "viewer":
				add(Scope{UnscopedCategory: "user"})
				continue
			case "rateLimit":
				add(Scope{UnscopedCategory: "meta"})
				continue
			}
			if len(s.SelectionSet) > 0 {
				collectGraphQLScopes(s.SelectionSet, fragments, vars, add)
			}
		case *ast.InlineFragment:
			collectGraphQLScopes(s.SelectionSet, fragments, vars, add)
		case *ast.FragmentSpread:
			if frag := fragments.ForName(s.Name); frag != nil {
				collectGraphQLScopes(frag.SelectionSet, fragments, vars, add)
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

// repoScopedIDPrefixes are GitHub's typed node-ID prefixes for objects that belong to
// a repository (pull requests, issues, reviews, comments, releases, the repo itself,
// labels, milestones, discussions). User/org/project/gist IDs are intentionally
// excluded so that mutations legitimately referencing them are not false-denied.
//
// Trade-off: this allowlist governs which node-ID mutations can be scoped. A
// repo-scoped node whose prefix is missing here would not be extracted — safe in
// isolation (no ID → unscoped write → denied) but a residual risk if it rode
// alongside an allowed ID. The authoritative resolver (proxy) means every extracted
// ID is checked against its REAL repository; the only remaining gap is prefix
// coverage, so keep this list broad for repo-scoped types.
var repoScopedIDPrefixes = []string{
	"PR_", "PRR_", "PRRC_", "PRRT_", // pull requests, reviews, review comments/threads
	"I_", "IC_", // issues, issue comments
	"CC_",        // commit comments
	"RE_",        // releases
	"R_",         // repositories
	"LA_", "MI_", // labels, milestones
	"D_", "DC_", // discussions, discussion comments
}

func isRepoScopedNodeID(s string) bool {
	for _, p := range repoScopedIDPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func isIDKeyName(name string) bool {
	n := strings.ToLower(name)
	return strings.HasSuffix(n, "id") || strings.HasSuffix(n, "ids")
}

// collectMutationNodeIDs returns the repo-scoped node IDs a mutation references,
// from inline arguments (under id-typed argument/object-field names) and from
// variables (under id-typed keys). Over-collection is safe — every collected ID is
// independently resolved and policy-checked; missing one would be the dangerous case.
func collectMutationNodeIDs(ops ast.OperationList, vars map[string]interface{}) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(s string) {
		if s != "" && isRepoScopedNodeID(s) && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, op := range ops {
		if op.Operation != ast.Mutation {
			continue
		}
		walkSelectionArgs(op.SelectionSet, vars, add)
	}
	walkVarsForIDs("", vars, add)
	return out
}

func walkSelectionArgs(sels ast.SelectionSet, vars map[string]interface{}, add func(string)) {
	for _, sel := range sels {
		if f, ok := sel.(*ast.Field); ok {
			for _, arg := range f.Arguments {
				walkArgValue(arg.Name, arg.Value, vars, add)
			}
			if len(f.SelectionSet) > 0 {
				walkSelectionArgs(f.SelectionSet, vars, add)
			}
		}
	}
}

func walkArgValue(name string, v *ast.Value, vars map[string]interface{}, add func(string)) {
	if v == nil {
		return
	}
	switch v.Kind {
	case ast.StringValue:
		if isIDKeyName(name) {
			add(v.Raw)
		}
	case ast.Variable:
		if isIDKeyName(name) {
			if s, ok := vars[v.Raw].(string); ok {
				add(s)
			}
		}
	case ast.ObjectValue:
		for _, child := range v.Children {
			walkArgValue(child.Name, child.Value, vars, add)
		}
	case ast.ListValue:
		for _, child := range v.Children {
			walkArgValue(name, child.Value, vars, add)
		}
	}
}

func walkVarsForIDs(key string, v interface{}, add func(string)) {
	switch val := v.(type) {
	case string:
		if isIDKeyName(key) {
			add(val)
		}
	case map[string]interface{}:
		for k, child := range val {
			walkVarsForIDs(k, child, add)
		}
	case []interface{}:
		for _, child := range val {
			walkVarsForIDs(key, child, add)
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

var gqlMetadataFields = map[string]bool{
	"name": true, "owner": true, "url": true, "id": true,
	"isPrivate": true, "isFork": true, "isArchived": true,
	"stargazers": true, "watchers": true, "description": true,
	"licenseInfo": true, "repositoryTopics": true, "languages": true,
	"forkCount": true, "stargazerCount": true, "visibility": true,
	"createdAt": true, "updatedAt": true,
}

func gqlMutationResource(name string) string {
	if strings.Contains(name, "PullRequest") ||
		name == "mergeBranch" ||
		name == "enablePullRequestAutoMerge" ||
		name == "disablePullRequestAutoMerge" {
		return "pulls"
	}
	if strings.Contains(name, "Issue") {
		return "issues"
	}
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
