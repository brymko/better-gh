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

// Round-12 audit H2/H3: a node-ID mutation's per-resource key must come from the RESOLVED node
// TYPE (PullRequest→pulls, Issue→issues), not the mutation field name — so addComment/addReaction
// /lockLockable (gqlMutationResource→"") can no longer write a PR under pulls=none, while the same
// mutation on an Issue is still allowed when issues is writable. mergeBranch is "branches".
func TestSec_MutationResourceFromResolvedType(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}

	// policy: base read-write on o/rw, but pulls and branches are off-limits; issues writable.
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{{
			Name:   "o/rw",
			Access: policy.AccessReadWrite,
			Permissions: map[string]policy.Access{
				"pulls":    policy.AccessNone,
				"branches": policy.AccessNone,
				"issues":   policy.AccessReadWrite,
			},
		}},
	}

	cases := []struct {
		name         string
		mutation     string
		nodeType     string // what the resolve query returns for the referenced node
		wantUpstream bool   // true → expect the mutation forwarded (allowed); false → denied 403
	}{
		{"addComment-on-PR-denied", `{"query":"mutation($id:ID!){addComment(input:{subjectId:$id,body:\"x\"}){clientMutationId}}","variables":{"id":"PR_x"}}`, "PullRequest", false},
		{"addComment-on-Issue-allowed", `{"query":"mutation($id:ID!){addComment(input:{subjectId:$id,body:\"x\"}){clientMutationId}}","variables":{"id":"I_x"}}`, "Issue", true},
		{"addLabels-on-PR-denied", `{"query":"mutation($id:ID!){addLabelsToLabelable(input:{labelableId:$id,labelIds:[\"L\"]}){clientMutationId}}","variables":{"id":"PR_x"}}`, "PullRequest", false},
		{"mergeBranch-denied-branches", `{"query":"mutation($r:ID!){mergeBranch(input:{repositoryId:$r,base:\"a\",head:\"b\"}){mergeCommit{oid}}}","variables":{"r":"R_x"}}`, "Repository", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forwarded := false
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/json")
				if strings.Contains(string(body), "nodes(ids") {
					// Resolve the referenced node to o/rw with the case's type. Repository reports
					// its own nameWithOwner; other repo-scoped types report repository{nameWithOwner}.
					if tc.nodeType == "Repository" {
						io.WriteString(w, `{"data":{"nodes":[{"__typename":"Repository","nameWithOwner":"o/rw"}]}}`)
					} else {
						io.WriteString(w, `{"data":{"nodes":[{"__typename":"`+tc.nodeType+`","repository":{"nameWithOwner":"o/rw"}}]}}`)
					}
					return
				}
				forwarded = true // the mutation itself reached upstream
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
			srv := httptest.NewServer(h)
			t.Cleanup(srv.Close)

			resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(tc.mutation))
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()

			if tc.wantUpstream {
				if resp.StatusCode != http.StatusOK || !forwarded {
					t.Fatalf("expected allowed+forwarded, got status %d forwarded=%v", resp.StatusCode, forwarded)
				}
			} else {
				if resp.StatusCode != http.StatusForbidden {
					t.Fatalf("expected 403 (per-resource deny), got %d", resp.StatusCode)
				}
				if forwarded {
					t.Fatalf("denied mutation must NOT reach upstream")
				}
			}
		})
	}
}
