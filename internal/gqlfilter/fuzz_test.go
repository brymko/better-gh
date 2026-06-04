package gqlfilter

import (
	"encoding/json"
	"testing"
)

// FuzzAugment ensures query augmentation never panics on arbitrary input (it validates
// against the schema and must fail closed with an error, not crash the proxy).
func FuzzAugment(f *testing.F) {
	s, err := Load()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(`query{repository(owner:"o",name:"r"){name issues(first:1){nodes{title}}}}`)
	f.Add(`query{viewer{login}}`)
	f.Add(`mutation{closePullRequest(input:{pullRequestId:"PR_x"}){clientMutationId}}`)
	f.Add(`query{repository(owner:"o",name:"r"){forks(first:1){nodes{name bghRepoTagZ9:name}}}}`)
	f.Add(``)
	f.Fuzz(func(t *testing.T, q string) {
		_, _ = s.Augment(q) // must not panic
	})
}

// FuzzFilter ensures response filtering never panics on arbitrary JSON (it processes
// GitHub's response bytes; a panic there would crash the proxy).
func FuzzFilter(f *testing.F) {
	f.Add([]byte(`{"data":{"repository":{"bghRepoTagZ9":"o/r","name":"r"}}}`))
	f.Add([]byte(`{"data":{"x":[{"bghRepoTagZ9":{"nameWithOwner":"o/denied"}}]}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var m map[string]any
		if json.Unmarshal(data, &m) != nil || m == nil {
			return
		}
		_ = Filter(m, func(owner, repo, _, _ string) bool { return owner == "o" && repo == "r" }) // must not panic
	})
}
