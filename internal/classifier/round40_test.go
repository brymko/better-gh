package classifier

import "testing"

func r40ScopesRepo(r Result, owner, repo string) bool {
	for _, s := range r.AllScopes() {
		if s.Owner == owner && s.Repo == repo {
			return true
		}
	}
	return false
}

// TestR40_CreateSponsorsTierSplitTargetScoped pins the round-40 finding-6 fix: a mutation naming its repo
// target by SEPARATE owner+name fields (createSponsorsTier's repositoryOwnerLogin + repositoryName) is scoped,
// so it cannot ride a benign carrier node past a per-repo `none` (the round-37 string-target sibling).
func TestR40_CreateSponsorsTierSplitTargetScoped(t *testing.T) {
	q := `mutation { createSponsorsTier(input:{amount:5, description:"d", repositoryName:"secret", repositoryOwnerLogin:"victimorg", sponsorableLogin:"victimorg"}){ clientMutationId } }`
	r := Classify("POST", "/graphql", []byte(`{"query":`+jsonStr(q)+`}`))
	if !r40ScopesRepo(r, "victimorg", "secret") {
		t.Errorf("createSponsorsTier split repo target (repositoryName+repositoryOwnerLogin) not scoped: %+v", r.AllScopes())
	}
}
