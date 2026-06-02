package classifier

import "testing"

// Covers what `gh repo list` actually sends: a schema-introspection query first, then the
// repositories query. Introspection must be classified as "meta" (not denied), or `gh repo
// list` 403s before it ever reads a repo.
func TestRepoListClassification(t *testing.T) {
	viewer := `{"query":"query RepositoryList($perPage:Int!){repositoryOwner: viewer{login repositories(first:$perPage,ownerAffiliations:OWNER){nodes{nameWithOwner}}}}","variables":{"perPage":30}}`
	withOwner := `{"query":"query RepositoryList($owner:String!,$perPage:Int!){repositoryOwner(login:$owner){repositories(first:$perPage){nodes{nameWithOwner}}}}","variables":{"owner":"octocat","perPage":30}}`
	introspect := `{"query":"query Repository_fields{Repository: __type(name: \"Repository\"){fields(includeDeprecated: true){name}}}"}`
	orgList := `{"query":"query OrganizationList($user:String!,$limit:Int!){user(login:$user){login organizations(first:$limit){nodes{login}}}}","variables":{"user":"octocat","limit":30}}`

	for _, tc := range []struct {
		name, body, wantCat, wantOrg string
	}{
		{"viewer (no owner)", viewer, "user", ""},
		{"repositoryOwner(login:$owner)", withOwner, "", "octocat"},
		{"schema introspection", introspect, "meta", ""},
		{"user(login:) — gh org list", orgList, "", "octocat"},
	} {
		r := Classify("POST", "/api/graphql", []byte(tc.body))
		if r.UnscopedCategory != tc.wantCat || r.Org != tc.wantOrg {
			t.Errorf("%s: category=%q org=%q — want category=%q org=%q", tc.name, r.UnscopedCategory, r.Org, tc.wantCat, tc.wantOrg)
		}
	}
}
