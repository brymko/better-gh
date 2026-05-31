package classifier

import (
	"slices"
	"testing"
)

func sameResult(a, b Result) bool {
	if a.Owner != b.Owner || a.Repo != b.Repo || a.Org != b.Org ||
		a.Access != b.Access || a.Resource != b.Resource || a.UnscopedCategory != b.UnscopedCategory {
		return false
	}
	if !slices.Equal(a.NodeIDs, b.NodeIDs) {
		return false
	}
	if len(a.Additional) != len(b.Additional) {
		return false
	}
	for i := range a.Additional {
		if a.Additional[i] != b.Additional[i] {
			return false
		}
	}
	return true
}

// checkInvariants asserts the safety properties classification must always hold,
// regardless of input: it never panics/loops (fuzzing exercises that), it returns a
// valid access level, it is deterministic (a non-deterministic classifier would make
// policy decisions unpredictable), and HasRepo implies a non-empty owner+repo.
func checkInvariants(t *testing.T, method, path string, body []byte) {
	t.Helper()
	r1 := Classify(method, path, body)
	if r1.Access != Read && r1.Access != Write {
		t.Fatalf("invalid access level %d for %q %q %q", r1.Access, method, path, body)
	}
	if r1.HasRepo() && (r1.Owner == "" || r1.Repo == "") {
		t.Fatalf("HasRepo() true but owner=%q repo=%q", r1.Owner, r1.Repo)
	}
	for _, s := range r1.Additional {
		if (s.Owner != "") != (s.Repo != "") {
			t.Fatalf("additional scope half-populated: owner=%q repo=%q", s.Owner, s.Repo)
		}
	}
	if r2 := Classify(method, path, body); !sameResult(r1, r2) {
		t.Fatalf("non-deterministic classification for %q %q %q", method, path, body)
	}
}

func FuzzClassify(f *testing.F) {
	seeds := []struct{ m, p, b string }{
		{"GET", "/api/v3/repos/o/r/pulls", ""},
		{"POST", "/api/v3/repos/o/r/dispatches", "{}"},
		{"DELETE", "/api/v3/repos/o/r", ""},
		{"PUT", "/api/v3/orgs/acme/members/bob", ""},
		{"GET", "/api/v3/repos/o/r/../../x/y/pulls", ""},
		{"GET", "/api/v3/user/repos", ""},
		{"GET", "/api/v3/search/code", ""},
		{"GET", "/repositories/123/pulls", ""},
		{"HEAD", "/api/v3/repos/O/R/contents/x", ""},
		{"GET", "/", ""},
		{"POST", "/api/graphql", `{"query":"query{viewer{login}}"}`},
		{"POST", "/api/graphql", `{not json`},
	}
	for _, s := range seeds {
		f.Add(s.m, s.p, s.b)
	}
	f.Fuzz(func(t *testing.T, method, path, body string) {
		checkInvariants(t, method, path, []byte(body))
	})
}

func FuzzClassifyGraphQL(f *testing.F) {
	seeds := []string{
		`{"query":"query{viewer{login}}"}`,
		`{"query":"mutation{ mergePullRequest(input:{pullRequestId:\"PR_x\"}){__typename} }"}`,
		`{"query":"query{ a:repository(owner:\"a\",name:\"b\"){name} c:repository(owner:\"d\",name:\"e\"){pullRequest(number:1){title}} }"}`,
		`{"query":"query A{repository(owner:\"a\",name:\"b\"){name}} query B{repository(owner:\"c\",name:\"d\"){name}}","operationName":"B"}`,
		`{"query":"query{ ...A } fragment A on Query{ ...B } fragment B on Query{ ...A }"}`,
		`{"query":"query{ node(id:\"R_x\"){ __typename } }"}`,
		`{"query":"query($ids:[ID!]!){ nodes(ids:$ids){__typename} }","variables":{"ids":["PR_a","I_b","U_c"]}}`,
		`{"query":"{search(query:\"repo:a/b repo:c/d\",type:ISSUE,first:1){nodes{__typename}}}"}`,
		`{"query":"mutation($i:CreateIssueInput!){createIssue(input:$i){issue{id}}}","variables":{"i":{"repositoryId":"R_z"}}}`,
		`{"query":""}`,
		`{}`,
		`not json at all`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		checkInvariants(t, "POST", "/api/graphql", []byte(body))
	})
}
