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
		return Result{Access: Read}
	}

	var req struct {
		Query     string                 `json:"query"`
		Variables map[string]interface{} `json:"variables"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return Result{Access: Read}
	}

	doc, gqlErr := parser.ParseQuery(&ast.Source{Input: req.Query})
	if gqlErr != nil {
		return Result{Access: Read}
	}

	access := Read
	var mutationFieldName string
	for _, op := range doc.Operations {
		if op.Operation == ast.Mutation {
			access = Write
			for _, sel := range op.SelectionSet {
				if f, ok := sel.(*ast.Field); ok && !isScopeField(f.Name) {
					mutationFieldName = f.Name
					break
				}
			}
			break
		}
	}

	result := Result{Access: access}
	var repoField *ast.Field
	for _, op := range doc.Operations {
		extractGraphQLScope(op.SelectionSet, doc.Fragments, req.Variables, &result, &repoField)
		if result.HasRepo() || result.Org != "" {
			break
		}
	}

	if access == Write && mutationFieldName != "" {
		result.Resource = gqlMutationResource(mutationFieldName)
	} else if result.HasRepo() && repoField != nil {
		result.Resource = gqlRepoResource(repoField)
	} else if !result.HasRepo() && result.Org == "" {
		result.UnscopedCategory = gqlUnscopedCategory(doc)
	}

	return result
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

func extractGraphQLScope(selections ast.SelectionSet, fragments ast.FragmentDefinitionList, vars map[string]interface{}, result *Result, repoField **ast.Field) {
	for _, sel := range selections {
		switch s := sel.(type) {
		case *ast.Field:
			switch s.Name {
			case "repository":
				owner := resolveStringArg(s.Arguments, "owner", vars)
				name := resolveStringArg(s.Arguments, "name", vars)
				if owner != "" && name != "" {
					result.Owner = owner
					result.Repo = name
					*repoField = s
					return
				}
			case "organization", "repositoryOwner":
				login := resolveStringArg(s.Arguments, "login", vars)
				if login != "" {
					result.Org = login
					return
				}
			case "search":
				query := resolveStringArg(s.Arguments, "query", vars)
				if owner, repo, ok := parseSearchRepoQualifier(query); ok {
					result.Owner = owner
					result.Repo = repo
					return
				}
			}
			if len(s.SelectionSet) > 0 {
				extractGraphQLScope(s.SelectionSet, fragments, vars, result, repoField)
				if result.HasRepo() || result.Org != "" {
					return
				}
			}
		case *ast.InlineFragment:
			extractGraphQLScope(s.SelectionSet, fragments, vars, result, repoField)
			if result.HasRepo() || result.Org != "" {
				return
			}
		case *ast.FragmentSpread:
			frag := fragments.ForName(s.Name)
			if frag != nil {
				extractGraphQLScope(frag.SelectionSet, fragments, vars, result, repoField)
				if result.HasRepo() || result.Org != "" {
					return
				}
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

func parseSearchRepoQualifier(query string) (owner, repo string, ok bool) {
	for _, part := range strings.Fields(query) {
		if strings.HasPrefix(part, "repo:") {
			spec := part[len("repo:"):]
			if slash := strings.IndexByte(spec, '/'); slash > 0 && slash < len(spec)-1 {
				return spec[:slash], spec[slash+1:], true
			}
		}
	}
	return "", "", false
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
	return ""
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

// IsGHEAuthEndpoint returns true for paths that gh uses during auth
// and that should bypass policy (they don't access repo data).
func IsGHEAuthEndpoint(method, path string) bool {
	norm := NormalizePath(path)
	if norm == "/" || norm == "" {
		return method == http.MethodGet
	}
	if norm == "/user" || norm == "/user/" {
		return method == http.MethodGet
	}
	return false
}
