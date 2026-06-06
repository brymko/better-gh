package restfilter

import "testing"

// TestR41_CamelRepositoryNameScan pins the round-41 finding-4 fix: the org billing usage report names a denied
// repo by a camelCase `repositoryName` (qualified by org), which the Pass body-scan now recognizes.
func TestR41_CamelRepositoryNameScan(t *testing.T) {
	deny := func(ownerRepo string) bool { return ownerRepo != "acme/secret" }
	body := []byte(`{"usageItems":[{"product":"actions","repositoryName":"secret","netAmount":1.0},{"repositoryName":"public-ok"}]}`)
	if d, ok := ContainsDeniedRepo(body, "acme", deny); !ok || !d {
		t.Fatalf("denied repo named by a camelCase repositoryName not detected (ok=%v denied=%v)", ok, d)
	}
	if d, _ := ContainsDeniedRepo([]byte(`{"usageItems":[{"repositoryName":"public-ok"}]}`), "acme", deny); d {
		t.Fatalf("allowed camelCase repositoryName wrongly flagged")
	}
}
