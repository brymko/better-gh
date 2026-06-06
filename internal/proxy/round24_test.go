package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"better-gh/internal/audit"
	"better-gh/internal/gqlfilter"
	"better-gh/internal/nodecache"
	"better-gh/internal/policy"
)

// TestSec_R24_SharedRepoNodeMultiResourceWrite: a multi-root mutation whose two root fields share ONE
// repository node ID under DIFFERENT per-resource keys (createIssue→issues, createRef→branches) must have
// EACH resource policy-checked — a branches="none" createRef must not ride under a permitted issues=rw
// createIssue (round-24 HIGH; the first-wins resource dedup collapsed them).
func TestSec_R24_SharedRepoNodeMultiResourceWrite(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{{
			Name:   "o/rw",
			Access: policy.AccessRead,
			Permissions: map[string]policy.Access{
				"issues":   policy.AccessReadWrite,
				"branches": policy.AccessNone,
			},
		}},
	}
	mkServer := func(forwarded *bool) *httptest.Server {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(string(body), "nodes(ids") {
				io.WriteString(w, `{"data":{"nodes":[{"__typename":"Repository","nameWithOwner":"o/rw"}]}}`)
				return
			}
			*forwarded = true
			io.WriteString(w, `{"data":{}}`)
		}))
		t.Cleanup(upstream.Close)
		nc := nodecache.New(time.Minute)
		t.Cleanup(nc.Stop)
		h := &Handler{
			GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
			Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol,
			UpstreamURL: upstream.URL, GQLFilter: sch, NodeCache: nc,
		}
		s := httptest.NewServer(h)
		t.Cleanup(s.Close)
		return s
	}

	createIssue := `a: createIssue(input:{repositoryId:"R_x",title:"x"}){clientMutationId}`
	createRef := `b: createRef(input:{repositoryId:"R_x",name:"refs/heads/evil",oid:"deadbeef"}){clientMutationId}`
	cases := []struct {
		name, mutation string
		wantForbidden  bool
	}{
		{"issue-then-ref (bypass attempt)", "mutation { " + createIssue + " " + createRef + " }", true},
		{"ref-then-issue (reversed)", "mutation { " + createRef + " " + createIssue + " }", true},
		{"lone-createRef (control: denied)", "mutation { " + createRef + " }", true},
		{"lone-createIssue (control: allowed)", "mutation { " + createIssue + " }", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forwarded := false
			srv := mkServer(&forwarded)
			resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(`{"query":`+jsonStr(tc.mutation)+`}`))
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if tc.wantForbidden {
				if resp.StatusCode != http.StatusForbidden {
					t.Fatalf("branches=none write must be 403, got %d", resp.StatusCode)
				}
				if forwarded {
					t.Fatalf("denied mutation must NOT reach upstream")
				}
			} else if resp.StatusCode != http.StatusOK || !forwarded {
				t.Fatalf("permitted issues mutation must be allowed+forwarded, got %d forwarded=%v", resp.StatusCode, forwarded)
			}
		})
	}
}

// TestSec_R24_UserStarredDeniedRepo: GET/PUT/DELETE /user/starred/{owner}/{repo} must gate on the
// path-named repo, not just the `user` category — a denied private repo is otherwise an existence oracle
// (204 vs 404) and a stargazer-write target (round-24 LOW).
func TestSec_R24_UserStarredDeniedRepo(t *testing.T) {
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny, Unscoped: map[string]policy.Access{"user": policy.AccessReadWrite}},
		Repo:     []policy.RepoRule{{Name: "victim/secret", Access: policy.AccessNone}},
	}
	var upstreamHit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	srv := httptest.NewServer(r15Handler(t, pol, upstream.URL))
	t.Cleanup(srv.Close)
	for _, m := range []string{"GET", "PUT", "DELETE"} {
		upstreamHit = false
		req, _ := http.NewRequest(m, srv.URL+"/user/starred/victim/secret", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s /user/starred/victim/secret must be 403 (denied repo), got %d", m, resp.StatusCode)
		}
		if upstreamHit {
			t.Errorf("%s denied-repo star must not reach upstream (existence oracle)", m)
		}
	}
}
