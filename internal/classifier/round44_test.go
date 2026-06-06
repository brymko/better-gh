package classifier

import "testing"

// TestR44_PropertiesValuesRepoNamesScoped pins round-44 Finding 3: PATCH /orgs/{org}/properties/values names
// the target repos by BARE repository_names[] (qualified by the path org); each must become a scope so a
// per-repo `none` carve-out blocks writing custom-property values to a denied repo.
func TestR44_PropertiesValuesRepoNamesScoped(t *testing.T) {
	body := []byte(`{"repository_names":["secret-repo","ok-repo"],"properties":[{"property_name":"env","value":"prod"}]}`)
	r := Classify("PATCH", "/orgs/myorg/properties/values", body)
	want := map[string]bool{"secret-repo": false, "ok-repo": false}
	for _, s := range r.AllScopes() {
		if s.Owner == "myorg" && s.Resource == "properties" {
			if _, ok := want[s.Repo]; ok {
				want[s.Repo] = true
			}
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("repository_names[] entry %q not scoped as myorg/%s (a denied repo bypasses the carve-out): %+v", name, name, r.AllScopes())
		}
	}
}
