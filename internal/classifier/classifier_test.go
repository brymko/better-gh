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
	body := []byte(`{"query":"query($owner: String!) { repositoryOwner(login: $owner) { repositories(first: 30) { nodes { name } } } }","variables":{"owner":"brymko"}}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Org != "brymko" {
		t.Fatalf("expected org brymko, got %s", r.Org)
	}
	if r.HasRepo() {
		t.Fatal("should not have repo")
	}
}

func TestGraphQLMutationWithRepo(t *testing.T) {
	body := []byte(`{"query":"mutation($owner: String!, $name: String!, $input: CreateIssueInput!) { repository(owner: $owner, name: $name) { id } }","variables":{"owner":"octocat","name":"hello-world"}}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Owner != "octocat" || r.Repo != "hello-world" {
		t.Fatalf("expected octocat/hello-world, got %s/%s", r.Owner, r.Repo)
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
	if r.Access != Read {
		t.Fatal("expected Read for no body")
	}
}

func TestGraphQLInvalidJSON(t *testing.T) {
	r := Classify(http.MethodPost, "/graphql", []byte("not json"))
	if r.Access != Read {
		t.Fatal("expected Read for invalid JSON")
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
		{"/repos/o/r/something-unknown", ""},
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
			"mixed-resources-ambiguous",
			`{"query":"{ repository(owner: \"o\", name: \"r\") { pullRequests(first:1) { nodes { title } } issues(first:1) { nodes { title } } } }"}`,
			"",
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
	body := []byte(`{"query":"mutation { mergeBranch(input: {repositoryId: \"id\", base: \"main\", head: \"dev\"}) { mergeCommit { oid } } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Resource != "pulls" {
		t.Errorf("mergeBranch: Resource = %q, want %q", r.Resource, "pulls")
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
	body := []byte(`{"query":"{ repository(owner: \"o\", name: \"r\") { pullRequests(first:1) { nodes { title } } customField } }"}`)
	r := Classify(http.MethodPost, "/graphql", body)
	if r.Resource != "" {
		t.Errorf("resource + unknown field should be ambiguous (empty), got %q", r.Resource)
	}
}

func TestIsGHEAuthEndpoint(t *testing.T) {
	if !IsGHEAuthEndpoint(http.MethodGet, "/api/v3/") {
		t.Fatal("GET /api/v3/ should be auth endpoint")
	}
	if !IsGHEAuthEndpoint(http.MethodGet, "/api/v3/user") {
		t.Fatal("GET /api/v3/user should be auth endpoint")
	}
	if IsGHEAuthEndpoint(http.MethodPost, "/api/v3/") {
		t.Fatal("POST /api/v3/ should not be auth endpoint")
	}
	if IsGHEAuthEndpoint(http.MethodGet, "/api/v3/repos/o/r") {
		t.Fatal("GET /api/v3/repos/o/r should not be auth endpoint")
	}
}
