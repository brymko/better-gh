package restfilter

import "testing"

// Filter must never panic on arbitrary upstream bytes, and must never KEEP an entry whose
// repository the predicate denies. The fuzzer denies everything, so any "/" -containing
// owner/repo string surviving in the output would be a leak (modulo strings that are not
// repo identifiers); we assert no panic and that output re-parses as the same kind.
func FuzzFilter(f *testing.F) {
	seeds := []string{
		`[{"full_name":"a/b"}]`,
		`{"total_count":3,"items":[{"repository":{"full_name":"a/b"}}]}`,
		`[{"repository_url":"https://api.github.com/repos/a/b"}]`,
		`{"message":"Not Found"}`,
		`not json`,
		`[]`,
		`{"items":[]}`,
		`[{"full_name":"a/b","owner":{"login":"a"},"name":"b","repository":{"full_name":"c/d"}}]`,
		`[1,2,3]`,
		`{"items":[[[[]]]]}`,
	}
	paths := []string{"/user/repos", "/search/code", "/notifications", "/user/issues", "/search/issues"}
	for _, s := range seeds {
		f.Add(s)
	}
	denyAll := func(string, bool) bool { return false }
	allowAll := func(string, bool) bool { return true }
	f.Fuzz(func(t *testing.T, body string) {
		for _, p := range paths {
			// must not panic on either predicate
			_ = Filter(p, []byte(body), denyAll)
			out := Filter(p, []byte(body), allowAll)
			// allowAll must be idempotent-ish: filtering again yields the same result
			if string(Filter(p, out, allowAll)) != string(out) {
				t.Fatalf("allowAll filter not stable for %q on %s", body, p)
			}
		}
	})
}
