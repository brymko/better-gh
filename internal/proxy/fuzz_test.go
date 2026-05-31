package proxy

import (
	"encoding/json"
	"testing"
)

// FuzzParseResolvedNode ensures parsing one nodes(ids:) response element never panics on
// arbitrary input — it processes GitHub's response bytes, so a panic would crash the proxy.
func FuzzParseResolvedNode(f *testing.F) {
	f.Add([]byte(`{"__typename":"Issue","bghr0":{"nameWithOwner":"o/r"}}`))
	f.Add([]byte(`{"__typename":"Repository","bghr1":"o/r"}`))
	f.Add([]byte(`{"__typename":"User"}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"__typename":123,"bghr0":[1,2,3]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseResolvedNode(json.RawMessage(data)) // must not panic
	})
}
