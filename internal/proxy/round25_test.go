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

// TestSec_R25_NestedOrgMemberRoster: members="none" must be enforced on member-identity fields reached by
// NAVIGATION (teams{nodes{organization{membersWithRole}}}), not just at the org root — the response filter
// nulls them using the org login the augmenter injects (round-25 HIGH-2). The mock returns GitHub's
// response to the AUGMENTED query (bghOrgLoginZ9 present, as the proxy's injected field requests).
func TestSec_R25_NestedOrgMemberRoster(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org:      []policy.OrgRule{{Name: "acme", Access: policy.AccessRead, Permissions: map[string]policy.Access{"teams": policy.AccessRead, "members": policy.AccessNone}}},
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if !strings.Contains(string(body), "bghOrgLoginZ9") {
			t.Errorf("proxy did not inject the org-login marker into the forwarded query")
		}
		io.WriteString(w, `{"data":{"organization":{"bghOrgLoginZ9":"acme","teams":{"nodes":[{"organization":{"bghOrgLoginZ9":"acme",`+
			`"membersWithRole":{"nodes":[{"login":"secret-admin","email":"admin@acme.internal"}]}}}]}}}}`)
	}))
	t.Cleanup(upstream.Close)
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol, UpstreamURL: upstream.URL, GQLFilter: sch,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	q := `{"query":"{ organization(login:\"acme\"){ teams(first:1){ nodes{ organization{ membersWithRole(first:10){ nodes{ login email } } } } } } }"}`
	resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(q))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(b), "secret-admin") || strings.Contains(string(b), "admin@acme.internal") {
		t.Fatalf("nested member roster leaked past members=none: %s", b)
	}
	if strings.Contains(string(b), "bghOrgLoginZ9") {
		t.Fatalf("org-login marker leaked into the client response: %s", b)
	}
}

// TestSec_R25_NodeTypeStricterThanName: a mutation whose NAME maps to a permissive resource but whose
// referenced NODE is a stricter/different type must be checked against BOTH keys — unmarkIssueAsDuplicate
// ("issues") on a PullRequest node ("pulls") must obey pulls="none"; createLinkedBranch ("branches") on an
// Issue node ("issues") must obey issues="none" (round-25 HIGH-1/MED-1, the nodeResourceKeys union).
func TestSec_R25_NodeTypeStricterThanName(t *testing.T) {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, mutation, resolveType string
		idCount                     int
		perms                       map[string]policy.Access
		wantForbidden               bool
	}{
		{
			"unmark-on-PR-dodges-pulls",
			`{"query":"mutation { unmarkIssueAsDuplicate(input:{canonicalId:\"PR_a\",duplicateId:\"PR_b\"}){clientMutationId} }"}`,
			"PullRequest", 2,
			map[string]policy.Access{"issues": policy.AccessReadWrite, "pulls": policy.AccessNone},
			true,
		},
		{
			"createLinkedBranch-dodges-issues",
			`{"query":"mutation { createLinkedBranch(input:{issueId:\"I_x\",oid:\"0000000000000000000000000000000000000000\",name:\"b\"}){clientMutationId} }"}`,
			"Issue", 1,
			map[string]policy.Access{"branches": policy.AccessReadWrite, "issues": policy.AccessNone},
			true,
		},
		{
			"control-addComment-on-issue-allowed",
			`{"query":"mutation { addComment(input:{subjectId:\"I_x\",body:\"hi\"}){clientMutationId} }"}`,
			"Issue", 1,
			map[string]policy.Access{"issues": policy.AccessReadWrite},
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pol := &policy.Policy{
				Defaults: policy.Defaults{Mode: policy.ModeDeny},
				Repo:     []policy.RepoRule{{Name: "o/r", Access: policy.AccessRead, Permissions: tc.perms}},
			}
			forwarded := false
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/json")
				if strings.Contains(string(body), "nodes(ids") {
					node := `{"__typename":"` + tc.resolveType + `","repository":{"nameWithOwner":"o/r"}}`
					nodes := make([]string, tc.idCount)
					for i := range nodes {
						nodes[i] = node
					}
					io.WriteString(w, `{"data":{"nodes":[`+strings.Join(nodes, ",")+`]}}`)
					return
				}
				forwarded = true
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
			if tc.wantForbidden {
				if resp.StatusCode != http.StatusForbidden {
					t.Fatalf("expected 403 (stricter node-type resource), got %d", resp.StatusCode)
				}
				if forwarded {
					t.Fatal("denied mutation must NOT reach upstream")
				}
			} else if resp.StatusCode != http.StatusOK || !forwarded {
				t.Fatalf("permitted mutation must be allowed+forwarded, got %d forwarded=%v", resp.StatusCode, forwarded)
			}
		})
	}
}
