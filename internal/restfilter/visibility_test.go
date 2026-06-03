package restfilter

import (
	"strings"
	"testing"
)

// publicBaseline mimics the proxy's restfilter callback under defaults.public=read with no
// matching explicit rule: keep an entry ONLY if it is public.
func publicBaseline(_ string, isPrivate bool) bool { return !isPrivate }

// Under the public-repo baseline, a public entry is kept while a private one — and one whose
// `private` field is absent (unknown → private, fail closed) — is dropped, for both the array
// (repo list) and the search-item shapes.
func TestFilter_PublicBaselineRespectsVisibility(t *testing.T) {
	arr := []byte(`[{"full_name":"o/pub","private":false},{"full_name":"o/priv","private":true},{"full_name":"o/unknown"}]`)
	out := string(Filter("/user/repos", arr, publicBaseline))
	if !strings.Contains(out, "o/pub") {
		t.Fatalf("public repo dropped: %s", out)
	}
	if strings.Contains(out, "o/priv") {
		t.Fatalf("LEAK: private repo kept by baseline: %s", out)
	}
	if strings.Contains(out, "o/unknown") {
		t.Fatalf("LEAK: unknown-visibility repo kept (must fail closed): %s", out)
	}

	search := []byte(`{"total_count":2,"items":[` +
		`{"repository":{"full_name":"o/pub","private":false}},` +
		`{"repository":{"full_name":"o/priv","private":true}}]}`)
	sout := string(Filter("/search/code", search, publicBaseline))
	if !strings.Contains(sout, "o/pub") {
		t.Fatalf("public search item dropped: %s", sout)
	}
	if strings.Contains(sout, "o/priv") {
		t.Fatalf("LEAK: private search item kept by baseline: %s", sout)
	}
}
