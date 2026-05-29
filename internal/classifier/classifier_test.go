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
