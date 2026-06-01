package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"better-gh/internal/audit"
	"better-gh/internal/gqlfilter"
	"better-gh/internal/policy"
)

// The GraphQL response filter must not corrupt large integers (databaseIds, counts) beyond
// float64's 53-bit mantissa when it parses+redacts+re-marshals. 9007199254740993 (2^53+1)
// is the canonical value float64 rounds (to ...992); UseNumber must preserve it.
func TestSec_FilterPreservesLargeIntegerPrecision(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	const bigID = "9007199254740993" // 2^53 + 1
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"repository":{"bghRepoTagZ9":"o/r","bghRepoTypeZ9":"Repository","databaseId":`+bigID+`}}}`)
	}))
	t.Cleanup(upstream.Close)

	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo:     []policy.RepoRule{{Name: "o/r", Access: policy.AccessRead}},
	}
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol,
		UpstreamURL: upstream.URL, GQLFilter: sch,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	q := `query{repository(owner:"o",name:"r"){databaseId}}`
	resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(`{"query":`+jsonStr(q)+`}`))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(out), bigID) {
		t.Fatalf("large integer corrupted by filter (precision loss): want %s in %s", bigID, out)
	}
}
