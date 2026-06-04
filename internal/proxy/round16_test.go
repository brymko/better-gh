package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"time"

	"better-gh/internal/audit"
	"better-gh/internal/gqlfilter"
	"better-gh/internal/nodecache"
	"better-gh/internal/policy"
)

// round16Upstream mocks GitHub: it resolves node IDs (a "WF_" id is a repo-OWNED type with no repo
// path — Workflow — so resolves to a __typename and NO repository; a "PR_" id resolves to a normal
// repo-bearing PullRequest) and counts how often a non-resolve query is FORWARDED (a leak would
// require the denied object's content to be forwarded).
func round16Upstream(t *testing.T, forwarded *int32) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/repos/") && strings.Contains(r.URL.Path, "/compare/") {
			atomic.AddInt32(forwarded, 1)
			io.WriteString(w, `{"url":"https://github.com/allowed-org/app/compare/x","files":[]}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		bs := string(body)
		if strings.Contains(bs, "nodes(ids") {
			var req struct {
				Variables struct {
					IDs []string `json:"ids"`
				} `json:"variables"`
			}
			json.Unmarshal(body, &req)
			nodes := make([]any, 0, len(req.Variables.IDs))
			for _, id := range req.Variables.IDs {
				switch {
				case strings.HasPrefix(id, "WF_"): // repo-owned type with NO repo path
					nodes = append(nodes, map[string]any{"__typename": "Workflow"})
				case strings.HasPrefix(id, "PR_"):
					nodes = append(nodes, map[string]any{"__typename": "PullRequest", "repository": map[string]any{"nameWithOwner": "allowed-org/app"}})
				default:
					nodes = append(nodes, nil)
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"nodes": nodes}})
			return
		}
		// Any other graphql query is a FORWARDED read (would carry the leaked content).
		atomic.AddInt32(forwarded, 1)
		io.WriteString(w, `{"data":{"node":{"title":"ok"}}}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func round16Handler(t *testing.T, pol *policy.Policy, upstreamURL string) *httptest.Server {
	sch, err := gqlfilter.Load()
	if err != nil {
		t.Fatal(err)
	}
	nc := nodecache.New(30 * time.Minute)
	t.Cleanup(nc.Stop)
	h := &Handler{
		GithubToken: "t", Store: mustStore(t), Audit: audit.NewLogger(t.TempDir() + "/a.jsonl"),
		Client: &http.Client{}, Mode: SocketMode, SocketPolicy: pol,
		UpstreamURL: upstreamURL, GQLFilter: sch, NodeCache: nc,
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

// Round-16 HIGH-1: a node(id:) read whose object is a repo-OWNED type with no derivable repository
// path (Workflow/DeployKey/…) must be DENIED, not streamed unfiltered. Covered for the mode=allow
// lone-node form and the mode=deny piggyback-on-an-allowed-repo form.
func TestSec_E2E_RepoOwnedUnpathableNodeDenied(t *testing.T) {
	t.Run("mode=allow lone node read of a denied repo's Workflow is denied", func(t *testing.T) {
		var forwarded int32
		up := round16Upstream(t, &forwarded)
		pol := &policy.Policy{
			Defaults: policy.Defaults{Mode: policy.ModeAllow},
			Repo:     []policy.RepoRule{{Name: "secret-org/secret", Access: policy.AccessNone}},
		}
		srv := round16Handler(t, pol, up.URL)
		body := `{"query":"query{ node(id:\"WF_secret\"){ ... on Workflow { name state url } } }"}`
		resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("node(id:) read of a repo-owned-unpathable type must be denied, got %d: %s", resp.StatusCode, out)
		}
		if n := atomic.LoadInt32(&forwarded); n != 0 {
			t.Fatalf("denied node read must not be forwarded (leak), got %d forwards", n)
		}
	})

	t.Run("mode=deny piggyback Workflow node alongside an allowed repo is denied", func(t *testing.T) {
		var forwarded int32
		up := round16Upstream(t, &forwarded)
		pol := &policy.Policy{
			Defaults: policy.Defaults{Mode: policy.ModeDeny},
			Repo:     []policy.RepoRule{{Name: "allowed-org/app", Access: policy.AccessRead}},
		}
		srv := round16Handler(t, pol, up.URL)
		body := `{"query":"query{ repository(owner:\"allowed-org\",name:\"app\"){ name } node(id:\"WF_secret\"){ ... on Workflow { name url } } }"}`
		resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("piggybacked Workflow node read must be denied, got %d", resp.StatusCode)
		}
		if n := atomic.LoadInt32(&forwarded); n != 0 {
			t.Fatalf("denied piggyback must not be forwarded, got %d forwards", n)
		}
	})

	t.Run("control: a node resolving to an allowed repo is still permitted", func(t *testing.T) {
		var forwarded int32
		up := round16Upstream(t, &forwarded)
		pol := &policy.Policy{
			Defaults: policy.Defaults{Mode: policy.ModeDeny},
			Repo:     []policy.RepoRule{{Name: "allowed-org/app", Access: policy.AccessRead}},
		}
		srv := round16Handler(t, pol, up.URL)
		body := `{"query":"query{ node(id:\"PR_allowed\"){ ... on PullRequest { title } } }"}`
		resp, err := http.Post(srv.URL+"/graphql", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden {
			t.Fatalf("a node resolving to an allowed repo must NOT be denied (fix must be selective)")
		}
	})
}

// Round-16 MEDIUM-3: a cross-fork compare must be denied when the foreign fork owner is not
// permitted, and allowed when it is the (allowed) path repo.
func TestSec_E2E_CrossForkCompareDenied(t *testing.T) {
	var forwarded int32
	up := round16Upstream(t, &forwarded)
	pol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo:     []policy.RepoRule{{Name: "allowed-org/app", Access: policy.AccessRead}},
	}
	srv := round16Handler(t, pol, up.URL)

	// Cross-fork to a denied owner → 403, never forwarded.
	resp, err := http.Get(srv.URL + "/repos/allowed-org/app/compare/main...victim:secret")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-fork compare to a denied fork must be denied, got %d", resp.StatusCode)
	}
	if n := atomic.LoadInt32(&forwarded); n != 0 {
		t.Fatalf("denied cross-fork compare must not be forwarded, got %d", n)
	}

	// Same-repo compare → allowed (forwarded).
	resp2, err := http.Get(srv.URL + "/repos/allowed-org/app/compare/main...dev")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusForbidden {
		t.Fatalf("same-repo compare must be allowed, got 403")
	}
}
