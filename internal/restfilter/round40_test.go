package restfilter

import "testing"

// TestR40_BareRepositoryStringScan pins the round-40 finding-7 fix: a bare `repository` name string qualified
// by the path org (org artifact storage-records) is detected by the Pass body-scan, while an allowed one is not.
func TestR40_BareRepositoryStringScan(t *testing.T) {
	deny := func(ownerRepo string) bool { return ownerRepo != "acme/secret" }
	body := []byte(`{"total_count":1,"storage_records":[{"name":"x","digest":"sha","repository":"secret"}]}`)
	d, ok := ContainsDeniedRepo(body, "acme", deny)
	if !ok {
		t.Fatal("storage-records body failed to parse")
	}
	if !d {
		t.Fatalf("denied repo named by a bare `repository` string (qualified by org) not detected")
	}
	if dd, _ := ContainsDeniedRepo([]byte(`{"storage_records":[{"repository":"public-ok"}]}`), "acme", deny); dd {
		t.Fatalf("allowed bare `repository` string wrongly flagged")
	}
	// owner/repo form is also recognized directly.
	if d2, _ := ContainsDeniedRepo([]byte(`{"x":{"repository":"acme/secret"}}`), "", deny); !d2 {
		t.Fatalf("denied owner/repo `repository` string not detected")
	}
}
