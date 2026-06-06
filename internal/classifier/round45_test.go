package classifier

import "testing"

// TestR45_TeamCreateRepoNamesScoped pins round-45 F4: POST /orgs/{org}/teams grants the new team access to
// the full-name repos in repo_names[]; each must become a scope so a per-repo `none` carve-out blocks
// creating a team with access to a denied repo.
func TestR45_TeamCreateRepoNamesScoped(t *testing.T) {
	body := []byte(`{"name":"exfil","repo_names":["acme/secret","acme/ok"]}`)
	r := Classify("POST", "/orgs/acme/teams", body)
	want := map[string]bool{"secret": false, "ok": false}
	for _, s := range r.AllScopes() {
		if s.Owner == "acme" && s.Resource == "teams" {
			if _, ok := want[s.Repo]; ok {
				want[s.Repo] = true
			}
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("repo_names[] entry acme/%s not scoped (team-create grants a denied repo): %+v", name, r.AllScopes())
		}
	}
}
