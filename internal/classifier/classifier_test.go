package classifier

import (
	"net/http"
	"testing"
)

func TestRESTRepos(t *testing.T) {
	r := Classify(http.MethodGet, "/repos/octocat/hello/pulls", nil)
	if r.Owner != "octocat" || r.Repo != "hello" {
		t.Fatalf("expected octocat/hello, got %s/%s", r.Owner, r.Repo)
	}
	if r.Access != Read {
		t.Fatal("expected Read")
	}
}

func TestRESTReposGHEPrefix(t *testing.T) {
	r := Classify(http.MethodGet, "/api/v3/repos/owner/repo/pulls", nil)
	if r.Owner != "owner" || r.Repo != "repo" {
		t.Fatalf("expected owner/repo, got %s/%s", r.Owner, r.Repo)
	}
}

func TestRESTOrgs(t *testing.T) {
	r := Classify(http.MethodGet, "/api/v3/orgs/my-company/repos", nil)
	if r.Org != "my-company" {
		t.Fatalf("expected org my-company, got %s", r.Org)
	}
	if r.HasRepo() {
		t.Fatal("should not have repo")
	}
}

func TestRESTWriteMethod(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		r := Classify(method, "/repos/owner/repo/pulls", nil)
		if r.Access != Write {
			t.Fatalf("%s should be Write", method)
		}
	}
}

func TestRESTReadMethod(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		r := Classify(method, "/repos/owner/repo/pulls", nil)
		if r.Access != Read {
			t.Fatalf("%s should be Read", method)
		}
	}
}

func TestRESTUser(t *testing.T) {
	r := Classify(http.MethodGet, "/user", nil)
	if r.HasRepo() || r.Org != "" {
		t.Fatal("user endpoint should have no repo/org")
	}
}

func TestRESTSearch(t *testing.T) {
	r := Classify(http.MethodGet, "/search/repositories?q=test", nil)
	if r.HasRepo() || r.Org != "" {
		t.Fatal("search should have no repo/org")
	}
}

func TestGraphQLQuery(t *testing.T) {
	body := []byte(`{"query":"query { viewer { login } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Access != Read {
		t.Fatal("expected Read for query")
	}
}

func TestGraphQLMutation(t *testing.T) {
	body := []byte(`{"query":"mutation { addStar(input: {}) { id } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Access != Write {
		t.Fatal("expected Write for mutation")
	}
}

func TestGraphQLNamedMutation(t *testing.T) {
	body := []byte(`{"query":"mutation AddStar { addStar(input: {}) { id } }"}`)
	r := Classify(http.MethodPost, "/api/graphql", body)
	if r.Access != Write {
		t.Fatal("expected Write for named mutation")
	}
}

func TestGraphQLMutationWithParams(t *testing.T) {
	body := []byte(`{"query":"mutation($input: AddStarInput!) { addStar(input: $input) { id } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Access != Write {
		t.Fatal("expected Write for mutation with params")
	}
}

func TestGraphQLRepoWithOwnerNameVars(t *testing.T) {
	body := []byte(`{"query":"query($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { id } }","variables":{"owner":"octocat","name":"hello-world"}}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Owner != "octocat" || r.Repo != "hello-world" {
		t.Fatalf("expected octocat/hello-world, got %s/%s", r.Owner, r.Repo)
	}
	if r.Access != Read {
		t.Fatal("expected Read")
	}
}

func TestGraphQLRepoWithOwnerRepoVars(t *testing.T) {
	body := []byte(`{"query":"query IssueList($owner: String!, $repo: String!) { repository(owner: $owner, name: $repo) { issues { nodes { title } } } }","variables":{"owner":"octocat","repo":"hello-world"}}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Owner != "octocat" || r.Repo != "hello-world" {
		t.Fatalf("expected octocat/hello-world, got %s/%s", r.Owner, r.Repo)
	}
	if r.Access != Read {
		t.Fatal("expected Read")
	}
}

func TestGraphQLRepoInlineLiterals(t *testing.T) {
	body := []byte(`{"query":"{ repo_000: repository(owner: \"octocat\", name: \"hello-world\") { id } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Owner != "octocat" || r.Repo != "hello-world" {
		t.Fatalf("expected octocat/hello-world, got %s/%s", r.Owner, r.Repo)
	}
}

func TestGraphQLOrganization(t *testing.T) {
	body := []byte(`{"query":"query($owner: String!) { organization(login: $owner) { repositories { nodes { name } } } }","variables":{"owner":"my-org"}}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Org != "my-org" {
		t.Fatalf("expected org my-org, got %s", r.Org)
	}
	if r.HasRepo() {
		t.Fatal("should not have repo")
	}
	if r.Access != Read {
		t.Fatal("expected Read")
	}
}

func TestGraphQLRepositoryOwner(t *testing.T) {
	body := []byte(`{"query":"query($owner: String!) { repositoryOwner(login: $owner) { repositories(first: 30) { nodes { name } } } }","variables":{"owner":"octocat"}}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Org != "octocat" {
		t.Fatalf("expected org octocat, got %s", r.Org)
	}
	if r.HasRepo() {
		t.Fatal("should not have repo")
	}
}

func TestGraphQLMutationWithRepo(t *testing.T) {
	body := []byte(`{"query":"mutation($owner: String!, $name: String!, $input: CreateIssueInput!) { repository(owner: $owner, name: $name) { id } }","variables":{"owner":"octocat","name":"hello-world"}}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Owner != "" || r.Repo != "" {
		t.Fatalf("mutations should not extract scope from repository(), got %s/%s", r.Owner, r.Repo)
	}
	if r.Access != Write {
		t.Fatal("expected Write")
	}
}

func TestGraphQLSearchWithRepoQualifier(t *testing.T) {
	body := []byte(`{"query":"query($q: String!, $first: Int!) { search(query: $q, type: ISSUE, first: $first) { nodes { ... on Issue { title } } } }","variables":{"q":"repo:octocat/hello-world is:open is:issue","first":30}}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Owner != "octocat" || r.Repo != "hello-world" {
		t.Fatalf("expected octocat/hello-world, got %s/%s", r.Owner, r.Repo)
	}
	if r.Access != Read {
		t.Fatal("expected Read")
	}
}

func TestGraphQLSearchWithoutRepoQualifier(t *testing.T) {
	body := []byte(`{"query":"query($q: String!) { search(query: $q, type: REPOSITORY, first: 10) { nodes { ... on Repository { name } } } }","variables":{"q":"language:go stars:>100"}}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.HasRepo() || r.Org != "" {
		t.Fatal("search without repo: qualifier should be unscoped")
	}
}

func TestGraphQLViewerQuery(t *testing.T) {
	body := []byte(`{"query":"query { viewer { login } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.HasRepo() || r.Org != "" {
		t.Fatal("viewer query should be unscoped")
	}
	if r.Access != Read {
		t.Fatal("expected Read")
	}
}

func TestGraphQLNodeIDMutation(t *testing.T) {
	body := []byte(`{"query":"mutation($id: ID!) { addStar(input: {starrableId: $id}) { starrable { id } } }","variables":{"id":"MDEwOlJlcG9zaXRvcnkx"}}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.HasRepo() || r.Org != "" {
		t.Fatal("node-ID mutation should be unscoped")
	}
	if r.Access != Write {
		t.Fatal("expected Write")
	}
}

func TestGraphQLUnrelatedVariables(t *testing.T) {
	body := []byte(`{"query":"query($first: Int!) { viewer { repositories(first: $first) { nodes { name } } } }","variables":{"first":10}}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.HasRepo() || r.Org != "" {
		t.Fatal("variables without repo scope should be unscoped")
	}
	if r.Access != Read {
		t.Fatal("expected Read")
	}
}

func TestGraphQLNoBody(t *testing.T) {
	r := Classify(http.MethodPost, "/graphql", nil)
	if r.Access != Write {
		t.Fatal("expected Write for no body (fail-closed)")
	}
}

func TestGraphQLInvalidJSON(t *testing.T) {
	r := Classify(http.MethodPost, "/graphql", []byte("not json"))
	if r.Access != Write {
		t.Fatal("expected Write for invalid JSON (fail-closed)")
	}
}

func TestEffectiveOrg(t *testing.T) {
	r := Classify(http.MethodGet, "/repos/my-org/my-repo/pulls", nil)
	if r.EffectiveOrg() != "my-org" {
		t.Fatalf("expected my-org, got %s", r.EffectiveOrg())
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		in, out string
	}{
		{"/api/v3/repos/o/r", "/repos/o/r"},
		{"/api/v3/", "/"},
		{"/api/v3", "/"},
		{"/api/graphql", "/graphql"},
		{"/repos/o/r", "/repos/o/r"},
		{"/graphql", "/graphql"},
	}
	for _, tt := range tests {
		got := NormalizePath(tt.in)
		if got != tt.out {
			t.Errorf("NormalizePath(%q) = %q, want %q", tt.in, got, tt.out)
		}
	}
}

func TestRepoFullName(t *testing.T) {
	r := Result{Owner: "a", Repo: "b"}
	if r.RepoFullName() != "a/b" {
		t.Fatalf("got %s", r.RepoFullName())
	}
	r2 := Result{}
	if r2.RepoFullName() != "" {
		t.Fatal("empty result should give empty name")
	}
}

func TestRESTResourceExtraction(t *testing.T) {
	tests := []struct {
		path     string
		resource string
	}{
		{"/repos/o/r/pulls", "pulls"},
		{"/repos/o/r/pulls/42", "pulls"},
		{"/repos/o/r/issues", "issues"},
		{"/repos/o/r/issues/7/comments", "issues"},
		{"/repos/o/r/contents/README.md", "contents"},
		{"/repos/o/r/readme", "contents"},
		{"/repos/o/r/zipball/main", "contents"},
		{"/repos/o/r/tarball/main", "contents"},
		{"/repos/o/r/actions/runs", "actions"},
		{"/repos/o/r/releases", "releases"},
		{"/repos/o/r/releases/1", "releases"},
		{"/repos/o/r/git/refs", "git"},
		{"/repos/o/r/commits", "commits"},
		{"/repos/o/r/compare/main...dev", "commits"},
		{"/repos/o/r/branches", "branches"},
		{"/repos/o/r/branches/main", "branches"},
		{"/repos/o/r/check-runs/1", "checks"},
		{"/repos/o/r/check-suites/1", "checks"},
		{"/repos/o/r/statuses/abc", "checks"},
		{"/repos/o/r/comments", "comments"},
		{"/repos/o/r/hooks", "hooks"},
		{"/repos/o/r/deployments", "deployments"},
		{"/repos/o/r/environments", "deployments"},
		{"/repos/o/r/pages", "pages"},
		{"/repos/o/r/keys", "keys"},
		{"/repos/o/r/deploy-keys", "keys"},
		{"/repos/o/r/stargazers", "metadata"},
		{"/repos/o/r/subscribers", "metadata"},
		{"/repos/o/r/topics", "metadata"},
		{"/repos/o/r/languages", "metadata"},
		{"/repos/o/r/tags", "metadata"},
		{"/repos/o/r/forks", "metadata"},
		{"/repos/o/r/contributors", "metadata"},
		{"/repos/o/r/collaborators", "metadata"},
		{"/repos/o/r/teams", "metadata"},
		{"/repos/o/r/license", "metadata"},
		{"/repos/o/r/community", "metadata"},
		{"/repos/o/r/traffic", "metadata"},
		{"/repos/o/r", "metadata"},
		{"/repos/o/r/something-unknown", "unknown"},
	}
	for _, tt := range tests {
		r := Classify(http.MethodGet, tt.path, nil)
		if r.Resource != tt.resource {
			t.Errorf("Classify(%q).Resource = %q, want %q", tt.path, r.Resource, tt.resource)
		}
	}
}

func TestRESTUnscopedCategory(t *testing.T) {
	tests := []struct {
		path     string
		category string
	}{
		{"/user", "user"},
		{"/user/repos", "user"},
		{"/search/repositories", "search"},
		{"/gists", "gists"},
		{"/notifications", "notifications"},
		{"/events", "events"},
		{"/rate_limit", "meta"},
		{"/feeds", "meta"},
		{"/meta", "meta"},
		{"/octocat", "meta"},
		{"/zen", "meta"},
		{"/emojis", "meta"},
		{"/", "meta"},
		{"/something-unknown", ""},
	}
	for _, tt := range tests {
		r := Classify(http.MethodGet, tt.path, nil)
		if r.UnscopedCategory != tt.category {
			t.Errorf("Classify(%q).UnscopedCategory = %q, want %q", tt.path, r.UnscopedCategory, tt.category)
		}
	}
}

func TestGraphQLResourceExtraction(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		resource string
	}{
		{
			"pullRequests",
			`{"query":"{ repository(owner: \"o\", name: \"r\") { pullRequests(first:10) { nodes { title } } } }"}`,
			"pulls",
		},
		{
			"issues",
			`{"query":"{ repository(owner: \"o\", name: \"r\") { issues(first:10) { nodes { title } } } }"}`,
			"issues",
		},
		{
			"metadata-only",
			`{"query":"{ repository(owner: \"o\", name: \"r\") { name description stargazerCount } }"}`,
			"metadata",
		},
		{
			"releases",
			`{"query":"{ repository(owner: \"o\", name: \"r\") { releases(first:5) { nodes { tagName } } } }"}`,
			"releases",
		},
		{
			"branches-ref",
			`{"query":"{ repository(owner: \"o\", name: \"r\") { defaultBranchRef { name } } }"}`,
			"branches",
		},
		{
			// Mixed resources now classify to a concrete primary (alphabetically first) with
			// BOTH resource scopes emitted (see TestGraphQLRepoResourceMixedResourcesBothEnforced);
			// the old "" ("ambiguous") result was a per-resource bypass.
			"mixed-resources",
			`{"query":"{ repository(owner: \"o\", name: \"r\") { pullRequests(first:1) { nodes { title } } issues(first:1) { nodes { title } } } }"}`,
			"issues",
		},
		{
			"contents-object",
			`{"query":"{ repository(owner: \"o\", name: \"r\") { object(expression: \"HEAD:README.md\") { ... on Blob { text } } } }"}`,
			"contents",
		},
	}
	for _, tt := range tests {
		r := Classify(http.MethodPost, "/graphql", []byte(tt.query))
		if r.Resource != tt.resource {
			t.Errorf("%s: Resource = %q, want %q", tt.name, r.Resource, tt.resource)
		}
	}
}

func TestGraphQLMutationResource(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		resource string
	}{
		{
			"mergePullRequest",
			`{"query":"mutation { mergePullRequest(input: {pullRequestId: \"id\"}) { pullRequest { url } } }","variables":{"owner":"o","name":"r"}}`,
			"pulls",
		},
		{
			"createIssue",
			`{"query":"mutation($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { id } createIssue(input: {}) { issue { id } } }","variables":{"owner":"o","name":"r"}}`,
			"issues",
		},
		{
			"createRef",
			`{"query":"mutation($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { id } createRef(input: {}) { ref { name } } }","variables":{"owner":"o","name":"r"}}`,
			"branches",
		},
	}
	for _, tt := range tests {
		r := Classify(http.MethodPost, "/graphql", []byte(tt.query))
		if r.Resource != tt.resource {
			t.Errorf("%s: Resource = %q, want %q", tt.name, r.Resource, tt.resource)
		}
	}
}

func TestGraphQLUnscopedCategory(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		category string
	}{
		{
			"viewer",
			`{"query":"{ viewer { login } }"}`,
			"user",
		},
		{
			"search-no-repo",
			`{"query":"query { search(query: \"language:go\", type: REPOSITORY, first: 10) { nodes { ... on Repository { name } } } }"}`,
			"search",
		},
		{
			"rateLimit",
			`{"query":"{ rateLimit { remaining } }"}`,
			"meta",
		},
	}
	for _, tt := range tests {
		r := Classify(http.MethodPost, "/graphql", []byte(tt.query))
		if r.UnscopedCategory != tt.category {
			t.Errorf("%s: UnscopedCategory = %q, want %q", tt.name, r.UnscopedCategory, tt.category)
		}
	}
}

func TestRESTResourceWithGHEPrefix(t *testing.T) {
	r := Classify(http.MethodGet, "/api/v3/repos/o/r/pulls/42", nil)
	if r.Resource != "pulls" {
		t.Errorf("GHE prefix: Resource = %q, want %q", r.Resource, "pulls")
	}
	if r.Owner != "o" || r.Repo != "r" {
		t.Errorf("GHE prefix: scope = %s/%s, want o/r", r.Owner, r.Repo)
	}
}

func TestRESTResourceOnWriteMethod(t *testing.T) {
	r := Classify(http.MethodPost, "/repos/o/r/pulls", nil)
	if r.Resource != "pulls" {
		t.Errorf("POST pulls: Resource = %q, want %q", r.Resource, "pulls")
	}
	if r.Access != Write {
		t.Error("POST should be Write")
	}
}

func TestRESTUnscopedCategoryOnWrite(t *testing.T) {
	r := Classify(http.MethodPost, "/gists", nil)
	if r.UnscopedCategory != "gists" {
		t.Errorf("POST /gists: UnscopedCategory = %q, want %q", r.UnscopedCategory, "gists")
	}
	if r.Access != Write {
		t.Error("POST should be Write")
	}
}

func TestGraphQLRepoResourceWithMetadataMix(t *testing.T) {
	body := []byte(`{"query":"{ repository(owner: \"o\", name: \"r\") { pullRequests(first:1) { nodes { title } } name } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Resource != "pulls" {
		t.Errorf("pulls+name: Resource = %q, want %q", r.Resource, "pulls")
	}
}

func TestGraphQLMutationResourceDeleteRelease(t *testing.T) {
	body := []byte(`{"query":"mutation { deleteRelease(input: {releaseId: \"id\"}) { release { id } } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Resource != "releases" {
		t.Errorf("deleteRelease: Resource = %q, want %q", r.Resource, "releases")
	}
}

func TestGraphQLMutationResourceUpdateCheck(t *testing.T) {
	body := []byte(`{"query":"mutation { updateCheckRun(input: {checkRunId: \"id\"}) { checkRun { id } } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Resource != "checks" {
		t.Errorf("updateCheckRun: Resource = %q, want %q", r.Resource, "checks")
	}
}

func TestGraphQLMutationResourceDeployment(t *testing.T) {
	body := []byte(`{"query":"mutation { createDeployment(input: {}) { deployment { id } } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Resource != "deployments" {
		t.Errorf("createDeployment: Resource = %q, want %q", r.Resource, "deployments")
	}
}

func TestGraphQLMutationUnknown(t *testing.T) {
	body := []byte(`{"query":"mutation { addStar(input: {starrableId: \"id\"}) { starrable { id } } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Resource != "" {
		t.Errorf("addStar: Resource = %q, want empty", r.Resource)
	}
}

func TestGraphQLSearchWithRepoQualifierResource(t *testing.T) {
	body := []byte(`{"query":"query($q: String!) { search(query: $q, type: ISSUE, first: 10) { nodes { ... on Issue { title } } } }","variables":{"q":"repo:octocat/hello is:open"}}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Owner != "octocat" || r.Repo != "hello" {
		t.Fatalf("expected octocat/hello, got %s/%s", r.Owner, r.Repo)
	}
	if r.Resource != "" {
		t.Errorf("search-resolved repo should have empty resource, got %q", r.Resource)
	}
}

func TestGraphQLOrgScopedHasNoResourceOrCategory(t *testing.T) {
	body := []byte(`{"query":"query { organization(login: \"my-org\") { repositories(first:10) { nodes { name } } } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Org != "my-org" {
		t.Fatalf("expected org my-org, got %s", r.Org)
	}
	if r.Resource != "" {
		t.Errorf("org-scoped should have empty resource, got %q", r.Resource)
	}
	if r.UnscopedCategory != "" {
		t.Errorf("org-scoped should have empty unscopedCategory, got %q", r.UnscopedCategory)
	}
}

func TestGraphQLMutationMergeBranch(t *testing.T) {
	// mergeBranch advances a branch tip (merge commit on the base branch), so it is a
	// "branches" write — not "pulls". Mapping it to pulls let it escape a branches="none"
	// rule under pulls="read-write" (round-12 audit H3).
	body := []byte(`{"query":"mutation { mergeBranch(input: {repositoryId: \"id\", base: \"main\", head: \"dev\"}) { mergeCommit { oid } } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Resource != "branches" {
		t.Errorf("mergeBranch: Resource = %q, want %q", r.Resource, "branches")
	}
}

func TestGraphQLMutationEnablePRAutoMerge(t *testing.T) {
	body := []byte(`{"query":"mutation { enablePullRequestAutoMerge(input: {pullRequestId: \"id\"}) { pullRequest { id } } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Resource != "pulls" {
		t.Errorf("enablePullRequestAutoMerge: Resource = %q, want %q", r.Resource, "pulls")
	}
}

func TestGraphQLMutationDisablePRAutoMerge(t *testing.T) {
	body := []byte(`{"query":"mutation { disablePullRequestAutoMerge(input: {pullRequestId: \"id\"}) { pullRequest { id } } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Resource != "pulls" {
		t.Errorf("disablePullRequestAutoMerge: Resource = %q, want %q", r.Resource, "pulls")
	}
}

func TestGraphQLRepoResourceWithUnknownField(t *testing.T) {
	// Regression (per-resource bypass): mixing a restricted resource with an unmapped
	// sibling field must NOT drop the resource. The old classifier returned "" here, which
	// the policy engine treats as the rule's base access — letting `repository(){
	// pullRequests customField }` slip past a `pulls = "none"` rule. The pulls scope must
	// still be emitted (and a metadata scope for customField).
	body := []byte(`{"query":"{ repository(owner: \"o\", name: \"r\") { pullRequests(first:1) { nodes { title } } customField } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if !hasRepoResourceScope(r, "o", "r", "pulls") {
		t.Errorf("pulls+unknown must still emit a pulls scope, got %+v", r.AllScopes())
	}
}

func TestGraphQLRepoResourceTypename(t *testing.T) {
	body := []byte(`{"query":"{ repository(owner: \"o\", name: \"r\") { __typename } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Owner != "o" || r.Repo != "r" {
		t.Fatalf("expected o/r, got %s/%s", r.Owner, r.Repo)
	}
	if r.Resource != "metadata" {
		t.Errorf("__typename only: Resource = %q, want %q", r.Resource, "metadata")
	}
}

func TestGraphQLRepoResourceSameResourceDedup(t *testing.T) {
	body := []byte(`{"query":"{ repository(owner: \"o\", name: \"r\") { pullRequest(number:1) { title } pullRequests(first:10) { nodes { title } } } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Owner != "o" || r.Repo != "r" {
		t.Fatalf("expected o/r, got %s/%s", r.Owner, r.Repo)
	}
	if r.Resource != "pulls" {
		t.Errorf("pullRequest+pullRequests: Resource = %q, want %q", r.Resource, "pulls")
	}
}

func TestGraphQLRepoResourceOnlyUnknownFields(t *testing.T) {
	body := []byte(`{"query":"{ repository(owner: \"o\", name: \"r\") { customField anotherCustom } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Owner != "o" || r.Repo != "r" {
		t.Fatalf("expected o/r, got %s/%s", r.Owner, r.Repo)
	}
	if r.Resource != "metadata" {
		t.Errorf("unknown fields only: Resource = %q, want %q", r.Resource, "metadata")
	}
}

func TestRESTResourceDeepPath(t *testing.T) {
	r := Classify(http.MethodGet, "/repos/o/r/pulls/42/reviews", nil)
	if r.Resource != "pulls" {
		t.Errorf("deep path pulls: Resource = %q, want %q", r.Resource, "pulls")
	}
}

func TestRESTResourceDeepPathActions(t *testing.T) {
	r := Classify(http.MethodGet, "/repos/o/r/actions/workflows/1/runs", nil)
	if r.Resource != "actions" {
		t.Errorf("deep path actions: Resource = %q, want %q", r.Resource, "actions")
	}
}

func TestGraphQLMutationOnlyScopeFields(t *testing.T) {
	body := []byte(`{"query":"mutation($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { id } }","variables":{"owner":"o","name":"r"}}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Owner != "" || r.Repo != "" {
		t.Fatalf("mutations should not extract scope, got %s/%s", r.Owner, r.Repo)
	}
	if r.Access != Write {
		t.Fatal("expected Write for mutation")
	}
	if r.Resource != "" {
		t.Errorf("mutation with only scope fields: Resource = %q, want empty", r.Resource)
	}
}

func TestGraphQLRepoResourceInlineFragment(t *testing.T) {
	// Regression (per-resource bypass): a resource wrapped in an inline fragment must be
	// classified. The old classifier only scanned direct *ast.Field children, so
	// `repository(){ ...on Repository{ pullRequests } }` was seen as "metadata" → base
	// access, dodging a `pulls = "none"` rule. The pulls scope must now be emitted.
	body := []byte(`{"query":"{ repository(owner: \"o\", name: \"r\") { ... on Repository { pullRequests(first:1) { nodes { title } } } } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Owner != "o" || r.Repo != "r" {
		t.Fatalf("expected o/r, got %s/%s", r.Owner, r.Repo)
	}
	if !hasRepoResourceScope(r, "o", "r", "pulls") {
		t.Errorf("inline-fragment-wrapped pulls must emit a pulls scope, got %+v", r.AllScopes())
	}
}

// hasRepoResourceScope reports whether the classified result emits a scope for the given
// repo + per-resource key (checking every scope the request touches, not just the primary).
func hasRepoResourceScope(r Result, owner, repo, resource string) bool {
	for _, s := range r.AllScopes() {
		if s.Owner == owner && s.Repo == repo && s.Resource == resource {
			return true
		}
	}
	return false
}

// TestGraphQLRepoResourceMixedResourcesBothEnforced locks in the per-resource bypass fix:
// a repository() selection touching two resources must emit a scope for EACH, so a query
// can't combine a restricted resource with another to escape policy.
func TestGraphQLRepoResourceMixedResourcesBothEnforced(t *testing.T) {
	body := []byte(`{"query":"{ repository(owner: \"o\", name: \"r\") { pullRequests(first:1){nodes{title}} issues(first:1){nodes{title}} } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if !hasRepoResourceScope(r, "o", "r", "pulls") {
		t.Errorf("missing pulls scope, got %+v", r.AllScopes())
	}
	if !hasRepoResourceScope(r, "o", "r", "issues") {
		t.Errorf("missing issues scope, got %+v", r.AllScopes())
	}
}

func TestRESTOrgHasNoResourceOrCategory(t *testing.T) {
	r := Classify(http.MethodGet, "/orgs/my-org/repos", nil)
	if r.Resource != "" {
		t.Errorf("org REST: Resource = %q, want empty", r.Resource)
	}
	if r.UnscopedCategory != "" {
		t.Errorf("org REST: UnscopedCategory = %q, want empty", r.UnscopedCategory)
	}
}

func TestRESTUsersHasNoResourceOrCategory(t *testing.T) {
	r := Classify(http.MethodGet, "/users/octocat/repos", nil)
	if r.Resource != "" {
		t.Errorf("users REST: Resource = %q, want empty", r.Resource)
	}
	if r.UnscopedCategory != "" {
		t.Errorf("users REST: UnscopedCategory = %q, want empty", r.UnscopedCategory)
	}
}

func TestGraphQLValidJSONInvalidGQL(t *testing.T) {
	body := []byte(`{"query":"query { ??? broken }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Access != Write {
		t.Fatal("invalid GQL should default to Write (fail-closed)")
	}
	if r.HasRepo() || r.Org != "" {
		t.Fatal("invalid GQL should have no scope")
	}
}

func TestGraphQLSearchRepoQualifierNoSlash(t *testing.T) {
	body := []byte(`{"query":"query($q: String!) { search(query: $q, type: ISSUE, first: 10) { nodes { ... on Issue { title } } } }","variables":{"q":"repo:single is:open"}}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.HasRepo() {
		t.Fatal("repo:single (no slash) should not resolve to owner/repo")
	}
}

func TestGraphQLSearchRepoQualifierTrailingSlash(t *testing.T) {
	body := []byte(`{"query":"query($q: String!) { search(query: $q, type: ISSUE, first: 10) { nodes { ... on Issue { title } } } }","variables":{"q":"repo:owner/ is:open"}}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.HasRepo() {
		t.Fatal("repo:owner/ (trailing slash) should not resolve to owner/repo")
	}
}

func TestGraphQLSearchRepoQualifierLeadingSlash(t *testing.T) {
	body := []byte(`{"query":"query($q: String!) { search(query: $q, type: ISSUE, first: 10) { nodes { ... on Issue { title } } } }","variables":{"q":"repo:/repo is:open"}}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.HasRepo() {
		t.Fatal("repo:/repo (leading slash) should not resolve to owner/repo")
	}
}

func TestAccessLevelString(t *testing.T) {
	if Read.String() != "read" {
		t.Errorf("Read.String() = %q, want %q", Read.String(), "read")
	}
	if Write.String() != "write" {
		t.Errorf("Write.String() = %q, want %q", Write.String(), "write")
	}
}

func TestNormalizePathTrailingSlashGraphQL(t *testing.T) {
	got := NormalizePath("/api/graphql/")
	if got != "/graphql" {
		t.Errorf("NormalizePath(/api/graphql/) = %q, want %q", got, "/graphql")
	}
}

func TestIsGHEAuthEndpointUserTrailingSlash(t *testing.T) {
	if IsGHEAuthEndpoint(http.MethodGet, "/api/v3/user/") {
		t.Fatal("GET /api/v3/user/ should not be auth endpoint")
	}
}

func TestGraphQLFragmentSpreadWithRepoScope(t *testing.T) {
	body := []byte(`{"query":"query($owner: String!, $name: String!) { ...RepoFields } fragment RepoFields on Query { repository(owner: $owner, name: $name) { pullRequests(first:10) { nodes { title } } } }","variables":{"owner":"octocat","name":"hello"}}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Owner != "octocat" || r.Repo != "hello" {
		t.Fatalf("fragment spread: expected octocat/hello, got %s/%s", r.Owner, r.Repo)
	}
}

func TestGraphQLInlineFragmentTopLevelScope(t *testing.T) {
	body := []byte(`{"query":"query($owner: String!, $name: String!) { ... on Query { repository(owner: $owner, name: $name) { id } } }","variables":{"owner":"o","name":"r"}}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Owner != "o" || r.Repo != "r" {
		t.Fatalf("top-level inline fragment: expected o/r, got %s/%s", r.Owner, r.Repo)
	}
}

func TestGraphQLFragmentSpreadUndefined(t *testing.T) {
	body := []byte(`{"query":"query { ...UndefinedFragment }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.HasRepo() || r.Org != "" {
		t.Fatal("undefined fragment should not resolve scope")
	}
}

// --- Security audit tests ---

func TestSec_MalformedGraphQLDefaultsToWrite(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{"empty body", nil},
		{"invalid json", []byte("not json")},
		{"valid json invalid gql", []byte(`{"query":"mutation { ??? broken }"}`)},
		{"utf8 bom prefix", append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"query":"mutation { deleteRepository(input:{}) { id } }"}`)...)},
	}
	for _, tt := range tests {
		r := Classify(http.MethodPost, "/graphql", tt.body)
		if r.Access != Write {
			t.Errorf("%s: expected Write (fail-closed), got Read", tt.name)
		}
		if r.HasRepo() || r.Org != "" {
			t.Errorf("%s: malformed body should have no scope", tt.name)
		}
		if r.Resource != "" || r.UnscopedCategory != "" {
			t.Errorf("%s: malformed body should have no resource/category", tt.name)
		}
	}
}

func TestSec_MutationWithRepoFieldScopesToFirstMatch(t *testing.T) {
	body := []byte(`{
		"query": "mutation($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { id } mergePullRequest(input: {pullRequestId: \"PR_fromDeniedRepo\"}) { pullRequest { url } } }",
		"variables": {"owner": "allowed-org", "name": "allowed-repo"}
	}`)
	r := Classify(http.MethodPost, "/graphql", body)

	if r.Owner != "" || r.Repo != "" {
		t.Fatalf("mutations should not extract scope from repository(), got %s/%s", r.Owner, r.Repo)
	}
	if r.Access != Write {
		t.Fatal("expected Write")
	}
	if r.Resource != "pulls" {
		t.Fatalf("expected resource=pulls, got %q", r.Resource)
	}
}

func TestSec_UnscopedMutationHasNoRepoOrOrg(t *testing.T) {
	// Finding 3: a node-ID mutation with no repository() field and no
	// cache hit results in empty owner/repo/org. With default=allow,
	// this bypasses all repo-specific deny rules.
	body := []byte(`{
		"query": "mutation($id: ID!) { mergePullRequest(input: {pullRequestId: $id}) { pullRequest { url } } }",
		"variables": {"id": "PR_kwDOSomeNodeId"}
	}`)
	r := Classify(http.MethodPost, "/graphql", body)

	if r.Owner != "" || r.Repo != "" || r.Org != "" {
		t.Fatal("node-ID mutation should have no scope without cache")
	}
	if r.Access != Write {
		t.Fatal("expected Write")
	}
	if r.Resource != "pulls" {
		t.Fatalf("expected resource=pulls, got %q", r.Resource)
	}
}

func TestSec_MutationScopeDoesNotPreventDifferentTarget(t *testing.T) {
	body := []byte(`{
		"query": "mutation { repository(owner: \"good-org\", name: \"good-repo\") { id } createIssue(input: {repositoryId: \"R_kgDODifferentRepo\"}) { issue { id } } }",
		"variables": {}
	}`)
	r := Classify(http.MethodPost, "/graphql", body)

	if r.Owner != "" || r.Repo != "" {
		t.Fatalf("mutations should not extract scope, got %s/%s", r.Owner, r.Repo)
	}
	if r.Resource != "issues" {
		t.Fatalf("mutation resource should be issues, got %q", r.Resource)
	}
}

func TestIsGHEAuthEndpoint(t *testing.T) {
	if !IsGHEAuthEndpoint(http.MethodGet, "/api/v3/") {
		t.Fatal("GET /api/v3/ should be auth endpoint")
	}
	if IsGHEAuthEndpoint(http.MethodGet, "/api/v3/user") {
		t.Fatal("GET /api/v3/user should not be auth endpoint")
	}
	if IsGHEAuthEndpoint(http.MethodPost, "/api/v3/") {
		t.Fatal("POST /api/v3/ should not be auth endpoint")
	}
	if IsGHEAuthEndpoint(http.MethodGet, "/api/v3/repos/o/r") {
		t.Fatal("GET /api/v3/repos/o/r should not be auth endpoint")
	}
}
