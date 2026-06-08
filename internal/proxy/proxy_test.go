package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"better-gh/internal/audit"
	"better-gh/internal/nodecache"
	"better-gh/internal/policy"
	"better-gh/internal/store"
)

func mockGitHub() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}/pulls", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{{"number": 1, "title": "test PR"}})
	})
	mux.HandleFunc("POST /repos/{owner}/{repo}/pulls", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"number": 42, "title": "created"})
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"total_count": 0, "workflow_runs": []any{}})
	})
	mux.HandleFunc("POST /repos/{owner}/{repo}/issues", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"number": 1, "title": "test"})
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/issues", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{{"number": 1, "title": "test"}})
	})
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"login": "testuser"})
	})
	mux.HandleFunc("POST /user/repos", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"name": "test"})
	})
	mux.HandleFunc("GET /gists", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]any{})
	})
	mux.HandleFunc("GET /search/repositories", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"total_count": 0, "items": []any{}})
	})
	mux.HandleFunc("POST /graphql", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)
		if strings.Contains(bodyStr, "nodes(ids") {
			var req struct {
				Variables struct {
					IDs []string `json:"ids"`
				} `json:"variables"`
			}
			json.Unmarshal(body, &req)
			nodes := make([]any, 0, len(req.Variables.IDs))
			for _, id := range req.Variables.IDs {
				if strings.HasPrefix(id, "U_") || strings.HasPrefix(id, "O_") {
					// a real non-repo node: __typename present, no repository
					nodes = append(nodes, map[string]any{"__typename": "User"})
					continue
				}
				nwo := mockResolveID(id)
				if nwo == "" {
					nodes = append(nodes, nil)
					continue
				}
				nodes = append(nodes, map[string]any{
					"__typename": "PullRequest",
					"repository": map[string]any{"nameWithOwner": nwo},
				})
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"nodes": nodes}})
			return
		}
		if strings.Contains(bodyStr, "viewer") {
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"viewer": map[string]string{"login": "testuser"}}})
		} else if strings.Contains(bodyStr, "repository") {
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"repository": map[string]any{
						"pullRequest": map[string]any{
							"id":    "PR_kwDOTestNode123",
							"title": "test PR",
						},
					},
				},
			})
		} else if strings.Contains(bodyStr, "mergePullRequest") {
			json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{
					"mergePullRequest": map[string]any{
						"pullRequest": map[string]any{"url": "https://github.com/allowed-org/rw-repo/pull/1"},
					},
				},
			})
		} else {
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{}})
		}
	})
	return httptest.NewServer(mux)
}

// mockResolveID models GitHub's authoritative node-ID → repository resolution for
// tests. Only explicitly known IDs resolve; everything else is unresolved (null).
func mockResolveID(id string) string {
	switch {
	case id == "PR_kwDOTestNode123", strings.Contains(id, "AllowedRw"):
		return "allowed-org/rw-repo"
	case strings.Contains(id, "BlockedSecret"):
		return "blocked-org/secret"
	default:
		return ""
	}
}

func testStore(t *testing.T, tmpDir string) (*store.Store, string) {
	t.Helper()
	storePath := filepath.Join(tmpDir, "tokens.json")
	s, err := store.Open(storePath)
	if err != nil {
		t.Fatal(err)
	}

	pol := policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org:      []policy.OrgRule{{Name: "allowed-org", Access: policy.AccessRead}},
		Repo: []policy.RepoRule{
			{Name: "allowed-org/rw-repo", Access: policy.AccessReadWrite},
			{Name: "blocked-org/secret", Access: policy.AccessNone},
		},
	}

	_, secret, err := s.Create("test-token", pol)
	if err != nil {
		t.Fatal(err)
	}
	return s, secret
}

type testEnv struct {
	gheServer    *httptest.Server
	socketServer *http.Server
	socketPath   string
	secret       string
	tmpDir       string
	mockGH       *httptest.Server
	store        *store.Store
	nodeCache    *nodecache.Cache
}

func testAuditLogger(t *testing.T) *audit.Logger {
	t.Helper()
	l := audit.NewLogger(t.TempDir() + "/a.jsonl")
	t.Cleanup(l.Close)
	return l
}
func setup(t *testing.T) *testEnv {
	t.Helper()

	mock := mockGitHub()

	tmpDir := t.TempDir()
	socketPath := filepath.Join("/tmp", fmt.Sprintf("bgh-test-%d.sock", os.Getpid()))

	tokenStore, secret := testStore(t, tmpDir)
	auditLogger := testAuditLogger(t)

	transport := &http.Transport{}
	client := &http.Client{Transport: transport}

	nodeCache := nodecache.New(30 * time.Minute)

	gheHandler := &Handler{
		GithubToken: "fake-gh-token",
		Store:       tokenStore,
		Audit:       auditLogger,
		Client:      client,
		Mode:        GHEMode,
		UpstreamURL: mock.URL,
		NodeCache:   nodeCache,
	}

	socketPol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org:      []policy.OrgRule{{Name: "allowed-org", Access: policy.AccessRead}},
		Repo: []policy.RepoRule{
			{Name: "allowed-org/rw-repo", Access: policy.AccessReadWrite},
			{Name: "blocked-org/secret", Access: policy.AccessNone},
		},
	}

	socketHandler := &Handler{
		GithubToken:  "fake-gh-token",
		Store:        tokenStore,
		Audit:        auditLogger,
		Client:       client,
		Mode:         SocketMode,
		SocketPolicy: socketPol,
		UpstreamURL:  mock.URL,
		NodeCache:    nodeCache,
	}

	gheServer := httptest.NewServer(gheHandler)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	socketServer := &http.Server{Handler: socketHandler}
	go socketServer.Serve(ln)

	t.Cleanup(func() {
		gheServer.Close()
		socketServer.Close()
		mock.Close()
		nodeCache.Stop()
		os.Remove(socketPath)
	})

	return &testEnv{
		gheServer:    gheServer,
		socketServer: socketServer,
		socketPath:   socketPath,
		secret:       secret,
		tmpDir:       tmpDir,
		mockGH:       mock,
		store:        tokenStore,
		nodeCache:    nodeCache,
	}
}

func gheClient(secret string) *http.Client {
	return &http.Client{
		Transport: &authTransport{secret: secret, base: http.DefaultTransport},
	}
}

type authTransport struct {
	secret string
	base   http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "token "+t.secret)
	return t.base.RoundTrip(req)
}

func socketClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}
}

func TestGHE_UnauthorizedNoHeader(t *testing.T) {
	env := setup(t)
	resp, err := http.Get(env.gheServer.URL + "/api/v3/repos/allowed-org/rw-repo/pulls")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestGHE_UnauthorizedWrongSecret(t *testing.T) {
	env := setup(t)
	client := gheClient("wrong-secret")
	resp, err := client.Get(env.gheServer.URL + "/api/v3/repos/allowed-org/rw-repo/pulls")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestGHE_RootEndpoint(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret)
	resp, err := client.Get(env.gheServer.URL + "/api/v3/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	scopes := resp.Header.Get("X-OAuth-Scopes")
	if !strings.Contains(scopes, "repo") {
		t.Fatalf("expected X-OAuth-Scopes to contain 'repo', got %q", scopes)
	}
}

func TestGHE_DeniedUnknownRepo(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret)
	resp, err := client.Get(env.gheServer.URL + "/api/v3/repos/unknown/repo/pulls")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestGHE_DeniedBlockedRepo(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret)
	resp, err := client.Get(env.gheServer.URL + "/api/v3/repos/blocked-org/secret/pulls")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestGHE_DeniedWriteOnReadOnlyOrg(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret)
	resp, err := client.Post(env.gheServer.URL+"/api/v3/repos/allowed-org/other-repo/pulls", "application/json", strings.NewReader(`{"title":"pr"}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestGHE_GraphQLDeniedDefaultDeny(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret)
	resp, err := client.Post(env.gheServer.URL+"/api/graphql", "application/json",
		strings.NewReader(`{"query":"query { viewer { login } }"}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestSocket_NoTokenUsesSocketPolicy(t *testing.T) {
	env := setup(t)
	client := socketClient(env.socketPath)

	// Unknown repo denied by socket policy
	resp, err := client.Get("http://localhost/repos/unknown/repo/pulls")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for unknown repo, got %d", resp.StatusCode)
	}

	// Blocked repo denied by socket policy
	resp2, err := client.Get("http://localhost/repos/blocked-org/secret/pulls")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for blocked repo, got %d", resp2.StatusCode)
	}
}

func TestSocket_DeniedBlockedRepo(t *testing.T) {
	env := setup(t)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", env.socketPath)
			},
		},
	}
	req, _ := http.NewRequest("GET", "http://localhost/repos/blocked-org/secret/pulls", nil)
	req.Header.Set("Authorization", "token "+env.secret)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestGHE_RevokedTokenDenied(t *testing.T) {
	env := setup(t)

	env.store.Revoke("test-token")

	client := gheClient(env.secret)
	resp, err := client.Get(env.gheServer.URL + "/api/v3/repos/allowed-org/rw-repo/pulls")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestGHE_MultipleTokensDifferentPolicies(t *testing.T) {
	env := setup(t)

	readOnlyPol := policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org:      []policy.OrgRule{{Name: "allowed-org", Access: policy.AccessRead}},
	}
	_, roSecret, err := env.store.Create("read-only-token", readOnlyPol)
	if err != nil {
		t.Fatal(err)
	}

	roClient := gheClient(roSecret)
	resp, err := roClient.Post(env.gheServer.URL+"/api/v3/repos/allowed-org/rw-repo/pulls", "application/json", strings.NewReader(`{"title":"pr"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only token should deny writes, got %d", resp.StatusCode)
	}

	rwClient := gheClient(env.secret)
	resp2, err := rwClient.Get(env.gheServer.URL + "/api/v3/repos/allowed-org/rw-repo/pulls")
	if err != nil {
		t.Fatal(err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if strings.Contains(string(body2), "bgh:") {
		t.Fatalf("rw token should pass proxy auth+policy, got %d; body=%s", resp2.StatusCode, body2)
	}
}

func TestSocket_UnknownTokenFallsBackToSocketPolicy(t *testing.T) {
	env := setup(t)
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", env.socketPath)
			},
		},
	}

	// gh sends its own GitHub token which isn't a proxy token — should fall back to SocketPolicy
	req, _ := http.NewRequest("GET", "http://localhost/repos/unknown/repo/pulls", nil)
	req.Header.Set("Authorization", "token some-gh-token-not-a-proxy-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 (socket policy deny), got %d", resp.StatusCode)
	}
}

func TestNodeCacheEnrichesMutation(t *testing.T) {
	env := setup(t)
	client := socketClient(env.socketPath)

	queryBody := `{"query":"query { repository(owner: \"allowed-org\", name: \"rw-repo\") { pullRequest(number: 1) { id title } } }"}`
	resp, err := client.Post("http://localhost/graphql", "application/json", strings.NewReader(queryBody))
	if err != nil {
		t.Fatal(err)
	}
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("query should be allowed, got %d: %s", resp.StatusCode, respBody)
	}

	var gqlResp map[string]any
	json.Unmarshal(respBody, &gqlResp)
	data := gqlResp["data"].(map[string]any)
	repo := data["repository"].(map[string]any)
	pr := repo["pullRequest"].(map[string]any)
	nodeID := pr["id"].(string)

	if nodeID == "" {
		t.Fatal("expected node ID in query response")
	}

	mutationBody := fmt.Sprintf(`{"query":"mutation { mergePullRequest(input: {pullRequestId: $id}) { pullRequest { url } } }","variables":{"input":{"pullRequestId":%q}}}`, nodeID)
	resp2, err := client.Post("http://localhost/graphql", "application/json", strings.NewReader(mutationBody))
	if err != nil {
		t.Fatal(err)
	}
	resp2Body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("mutation with cached node ID should be allowed, got %d: %s", resp2.StatusCode, resp2Body)
	}
}

func setupWithPerms(t *testing.T) *testEnv {
	t.Helper()

	mock := mockGitHub()
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	socketPath := filepath.Join("/tmp", fmt.Sprintf("bgh-perm-test-%d.sock", os.Getpid()))

	storePath := filepath.Join(tmpDir, "tokens.json")
	tokenStore, err := store.Open(storePath)
	if err != nil {
		t.Fatal(err)
	}

	pol := policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org:      []policy.OrgRule{{Name: "allowed-org", Access: policy.AccessRead}},
		Repo: []policy.RepoRule{
			{
				Name:   "allowed-org/rw-repo",
				Access: policy.AccessRead,
				Permissions: map[string]policy.Access{
					"pulls":   policy.AccessReadWrite,
					"actions": policy.AccessNone,
				},
			},
		},
	}
	_, secret, err := tokenStore.Create("perm-token", pol)
	if err != nil {
		t.Fatal(err)
	}

	auditLogger := audit.NewLogger(auditPath)
	client := &http.Client{Transport: &http.Transport{}}
	nodeCache := nodecache.New(30 * time.Minute)

	gheHandler := &Handler{
		GithubToken: "fake-gh-token",
		Store:       tokenStore,
		Audit:       auditLogger,
		Client:      client,
		Mode:        GHEMode,
		UpstreamURL: mock.URL,
		NodeCache:   nodeCache,
	}

	socketPol := &policy.Policy{
		Defaults: policy.Defaults{
			Mode: policy.ModeDeny,
			Unscoped: map[string]policy.Access{
				"user":   policy.AccessRead,
				"search": policy.AccessRead,
			},
		},
		Org:  []policy.OrgRule{{Name: "allowed-org", Access: policy.AccessRead}},
		Repo: []policy.RepoRule{{Name: "allowed-org/rw-repo", Access: policy.AccessReadWrite}},
	}

	socketHandler := &Handler{
		GithubToken:  "fake-gh-token",
		Store:        tokenStore,
		Audit:        auditLogger,
		Client:       client,
		Mode:         SocketMode,
		SocketPolicy: socketPol,
		UpstreamURL:  mock.URL,
		NodeCache:    nodeCache,
	}

	gheServer := httptest.NewServer(gheHandler)

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	socketServer := &http.Server{Handler: socketHandler}
	go socketServer.Serve(ln)

	t.Cleanup(func() {
		gheServer.Close()
		socketServer.Close()
		mock.Close()
		nodeCache.Stop()
		os.Remove(socketPath)
	})

	return &testEnv{
		gheServer:    gheServer,
		socketServer: socketServer,
		socketPath:   socketPath,
		secret:       secret,
		tmpDir:       tmpDir,
		mockGH:       mock,
		store:        tokenStore,
		nodeCache:    nodeCache,
	}
}

func TestGHE_RepoPermAllowsPullsWrite(t *testing.T) {
	env := setupWithPerms(t)
	client := gheClient(env.secret)

	resp, err := client.Post(
		env.gheServer.URL+"/api/v3/repos/allowed-org/rw-repo/pulls",
		"application/json",
		strings.NewReader(`{"title":"test"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Fatal("pulls=read-write should allow POST to /pulls")
	}
}

func TestGHE_RepoPermBlocksActionsRead(t *testing.T) {
	env := setupWithPerms(t)
	client := gheClient(env.secret)

	resp, err := client.Get(env.gheServer.URL + "/api/v3/repos/allowed-org/rw-repo/actions/runs")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("actions=none should deny even GET, got %d", resp.StatusCode)
	}
}

func TestGHE_RepoPermFallsBackForIssues(t *testing.T) {
	env := setupWithPerms(t)
	client := gheClient(env.secret)

	resp, err := client.Post(
		env.gheServer.URL+"/api/v3/repos/allowed-org/rw-repo/issues",
		"application/json",
		strings.NewReader(`{"title":"bug"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("issues not in permissions, base access=read should deny POST, got %d", resp.StatusCode)
	}
}

func TestSocket_UnscopedUserReadAllowed(t *testing.T) {
	env := setupWithPerms(t)
	client := socketClient(env.socketPath)

	resp, err := client.Get("http://localhost/user")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Fatal("unscoped user=read should allow GET /user")
	}
}

func TestSocket_UnscopedUserWriteDenied(t *testing.T) {
	env := setupWithPerms(t)
	client := socketClient(env.socketPath)

	resp, err := client.Post("http://localhost/user/repos", "application/json", strings.NewReader(`{"name":"test"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unscoped user=read should deny POST /user/repos, got %d", resp.StatusCode)
	}
}

func TestSocket_UnscopedGistsDenied(t *testing.T) {
	env := setupWithPerms(t)
	client := socketClient(env.socketPath)

	resp, err := client.Get("http://localhost/gists")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("gists not in unscoped map, should be denied, got %d", resp.StatusCode)
	}
}

func TestSocket_UnscopedGraphQLViewerAllowed(t *testing.T) {
	env := setupWithPerms(t)
	client := socketClient(env.socketPath)

	resp, err := client.Post(
		"http://localhost/graphql",
		"application/json",
		strings.NewReader(`{"query":"query { viewer { login } }"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Fatal("unscoped user=read should allow viewer query")
	}
}

func TestAuditEntryContainsResourceAndCategory(t *testing.T) {
	env := setupWithPerms(t)
	client := socketClient(env.socketPath)

	client.Get("http://localhost/repos/allowed-org/rw-repo/pulls")
	client.Get("http://localhost/search/repositories?q=test")

	time.Sleep(100 * time.Millisecond)

	auditPath := filepath.Join(env.tmpDir, "audit.jsonl")
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	foundResource := false
	foundCategory := false
	for _, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if r, ok := entry["resource"].(string); ok && r == "pulls" {
			foundResource = true
		}
		if c, ok := entry["unscoped_category"].(string); ok && c == "search" {
			foundCategory = true
		}
	}
	if !foundResource {
		t.Error("audit log missing resource=pulls entry")
	}
	if !foundCategory {
		t.Error("audit log missing unscoped_category=search entry")
	}
}

func TestGHE_OrgPermAllowsPullsWrite(t *testing.T) {
	env := setup(t)

	orgPermPol := policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Org: []policy.OrgRule{{
			Name:   "allowed-org",
			Access: policy.AccessRead,
			Permissions: map[string]policy.Access{
				"pulls": policy.AccessReadWrite,
			},
		}},
	}
	_, secret, err := env.store.Create("org-perm-token", orgPermPol)
	if err != nil {
		t.Fatal(err)
	}

	client := gheClient(secret)

	resp, err := client.Post(
		env.gheServer.URL+"/api/v3/repos/allowed-org/rw-repo/pulls",
		"application/json",
		strings.NewReader(`{"title":"test"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Fatal("org pulls=read-write should allow POST to /pulls")
	}

	resp2, err := client.Post(
		env.gheServer.URL+"/api/v3/repos/allowed-org/rw-repo/issues",
		"application/json",
		strings.NewReader(`{"title":"bug"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("org issues should fall back to org access=read, deny POST, got %d", resp2.StatusCode)
	}
}

func TestGHE_UnscopedInTokenPolicy(t *testing.T) {
	env := setup(t)

	unscopedPol := policy.Policy{
		Defaults: policy.Defaults{
			Mode: policy.ModeDeny,
			Unscoped: map[string]policy.Access{
				"search": policy.AccessRead,
			},
		},
	}
	_, secret, err := env.store.Create("unscoped-token", unscopedPol)
	if err != nil {
		t.Fatal(err)
	}

	client := gheClient(secret)

	resp, err := client.Get(env.gheServer.URL + "/api/v3/search/repositories?q=test")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Fatal("unscoped search=read in token policy should allow GET /search/repositories")
	}

	resp2, err := client.Get(env.gheServer.URL + "/api/v3/gists")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("gists not in unscoped map, should be denied, got %d", resp2.StatusCode)
	}
}

func TestGHE_GraphQLResourcePermissions(t *testing.T) {
	env := setupWithPerms(t)
	client := gheClient(env.secret)

	queryBody := `{"query":"query { repository(owner: \"allowed-org\", name: \"rw-repo\") { pullRequests(first: 10) { nodes { title } } } }"}`
	resp, err := client.Post(
		env.gheServer.URL+"/api/graphql",
		"application/json",
		strings.NewReader(queryBody),
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Fatal("GraphQL pullRequests query on repo with pulls=read-write should be allowed")
	}
}

func TestSocket_PermissionsInSocketPolicy(t *testing.T) {
	mock := mockGitHub()
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	socketPath := filepath.Join("/tmp", fmt.Sprintf("bgh-sockperm-%d.sock", os.Getpid()))

	storePath := filepath.Join(tmpDir, "tokens.json")
	tokenStore, err := store.Open(storePath)
	if err != nil {
		t.Fatal(err)
	}

	auditLogger := audit.NewLogger(auditPath)
	client := &http.Client{Transport: &http.Transport{}}
	nodeCache := nodecache.New(30 * time.Minute)

	socketPol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo: []policy.RepoRule{{
			Name:   "org/repo",
			Access: policy.AccessRead,
			Permissions: map[string]policy.Access{
				"pulls":   policy.AccessReadWrite,
				"actions": policy.AccessNone,
			},
		}},
	}

	socketHandler := &Handler{
		GithubToken:  "fake-gh-token",
		Store:        tokenStore,
		Audit:        auditLogger,
		Client:       client,
		Mode:         SocketMode,
		SocketPolicy: socketPol,
		UpstreamURL:  mock.URL,
		NodeCache:    nodeCache,
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: socketHandler}
	go srv.Serve(ln)
	t.Cleanup(func() {
		srv.Close()
		mock.Close()
		nodeCache.Stop()
		os.Remove(socketPath)
	})

	sc := socketClient(socketPath)

	resp, err := sc.Post("http://localhost/repos/org/repo/pulls", "application/json", strings.NewReader(`{"title":"test"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Fatal("socket policy pulls=read-write should allow POST")
	}

	resp2, err := sc.Get("http://localhost/repos/org/repo/actions/runs")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("socket policy actions=none should deny GET, got %d", resp2.StatusCode)
	}

	resp3, err := sc.Get("http://localhost/repos/org/repo/issues")
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode == http.StatusForbidden {
		t.Fatal("socket policy issues should fall back to access=read and allow GET")
	}
}

func TestAuditEntryDeniedByResourcePermission(t *testing.T) {
	env := setupWithPerms(t)
	client := gheClient(env.secret)

	client.Get(env.gheServer.URL + "/api/v3/repos/allowed-org/rw-repo/actions/runs")

	time.Sleep(100 * time.Millisecond)

	auditPath := filepath.Join(env.tmpDir, "audit.jsonl")
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	found := false
	for _, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if r, ok := entry["resource"].(string); ok && r == "actions" {
			if pr, ok := entry["policy_result"].(string); ok && strings.Contains(pr, "denied") {
				found = true
			}
		}
	}
	if !found {
		t.Error("audit log should contain denied entry for resource=actions")
	}
}

func TestGHE_QueryStringPreserved(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret)

	resp, err := client.Get(env.gheServer.URL + "/api/v3/repos/allowed-org/rw-repo/pulls?state=closed&per_page=5")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Fatal("query string request should be allowed")
	}
}

func TestSocket_NoSocketPolicyDenies(t *testing.T) {
	mock := mockGitHub()
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	socketPath := filepath.Join("/tmp", fmt.Sprintf("bgh-nopol-%d.sock", os.Getpid()))

	storePath := filepath.Join(tmpDir, "tokens.json")
	tokenStore, err := store.Open(storePath)
	if err != nil {
		t.Fatal(err)
	}

	auditLogger := audit.NewLogger(auditPath)
	client := &http.Client{Transport: &http.Transport{}}
	nodeCache := nodecache.New(30 * time.Minute)

	socketHandler := &Handler{
		GithubToken:  "fake-gh-token",
		Store:        tokenStore,
		Audit:        auditLogger,
		Client:       client,
		Mode:         SocketMode,
		SocketPolicy: nil,
		UpstreamURL:  mock.URL,
		NodeCache:    nodeCache,
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: socketHandler}
	go srv.Serve(ln)
	t.Cleanup(func() {
		srv.Close()
		mock.Close()
		nodeCache.Stop()
		os.Remove(socketPath)
	})

	sc := socketClient(socketPath)
	resp, err := sc.Get("http://localhost/repos/any/repo/pulls")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("nil socket policy should deny, got %d", resp.StatusCode)
	}
}

func TestGHE_GraphQLMutationWithResourcePermission(t *testing.T) {
	env := setupWithPerms(t)
	client := gheClient(env.secret)

	body := `{"query":"mutation($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { id } createIssue(input: {}) { issue { id } } }","variables":{"owner":"allowed-org","name":"rw-repo"}}`
	resp, err := client.Post(
		env.gheServer.URL+"/api/graphql",
		"application/json",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("createIssue mutation: repo access=read with no issues perm should deny write, got %d", resp.StatusCode)
	}
}

func TestGHE_UpstreamFailureReturns502(t *testing.T) {
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")

	storePath := filepath.Join(tmpDir, "tokens.json")
	tokenStore, err := store.Open(storePath)
	if err != nil {
		t.Fatal(err)
	}

	pol := policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
		Repo:     []policy.RepoRule{{Name: "org/repo", Access: policy.AccessRead}},
	}
	_, secret, _ := tokenStore.Create("tok", pol)

	auditLogger := audit.NewLogger(auditPath)
	nodeCache := nodecache.New(30 * time.Minute)

	handler := &Handler{
		GithubToken: "fake-token",
		Store:       tokenStore,
		Audit:       auditLogger,
		Client:      &http.Client{Transport: &http.Transport{}},
		Mode:        GHEMode,
		UpstreamURL: "http://127.0.0.1:1",
		NodeCache:   nodeCache,
	}

	srv := httptest.NewServer(handler)
	t.Cleanup(func() {
		srv.Close()
		nodeCache.Stop()
	})

	client := gheClient(secret)
	resp, err := client.Get(srv.URL + "/api/v3/repos/org/repo/pulls")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 for unreachable upstream, got %d", resp.StatusCode)
	}

	time.Sleep(100 * time.Millisecond)
	data, _ := os.ReadFile(auditPath)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	found := false
	for _, line := range lines {
		var entry map[string]any
		json.Unmarshal([]byte(line), &entry)
		if entry["policy_result"] == "allowed" && entry["resource"] == "pulls" {
			found = true
		}
	}
	if !found {
		t.Error("upstream failure should still produce an audit entry with resource=pulls")
	}
}

func TestListenerModeString(t *testing.T) {
	if SocketMode.String() != "socket" {
		t.Errorf("SocketMode.String() = %q", SocketMode.String())
	}
	if GHEMode.String() != "ghe" {
		t.Errorf("GHEMode.String() = %q", GHEMode.String())
	}
}

// --- Security audit tests ---

func TestSec_UnscopedMutationWithDefaultAllow(t *testing.T) {
	mock := mockGitHub()
	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	socketPath := filepath.Join("/tmp", fmt.Sprintf("bgh-sec-unscoped-%d.sock", os.Getpid()))

	storePath := filepath.Join(tmpDir, "tokens.json")
	tokenStore, _ := store.Open(storePath)
	auditLogger := audit.NewLogger(auditPath)
	nodeCache := nodecache.New(30 * time.Minute)

	socketPol := &policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeAllow},
		Repo: []policy.RepoRule{
			{Name: "secret-org/secret-repo", Access: policy.AccessNone},
		},
	}

	socketHandler := &Handler{
		GithubToken:  "fake-gh-token",
		Store:        tokenStore,
		Audit:        auditLogger,
		Client:       &http.Client{Transport: &http.Transport{}},
		Mode:         SocketMode,
		SocketPolicy: socketPol,
		UpstreamURL:  mock.URL,
		NodeCache:    nodeCache,
	}

	ln, _ := net.Listen("unix", socketPath)
	srv := &http.Server{Handler: socketHandler}
	go srv.Serve(ln)
	t.Cleanup(func() {
		srv.Close()
		mock.Close()
		nodeCache.Stop()
		os.Remove(socketPath)
	})

	sc := socketClient(socketPath)

	body := `{"query":"mutation($id: ID!) { mergePullRequest(input: {pullRequestId: $id}) { pullRequest { url } } }","variables":{"id":"PR_kwDOFromDeniedRepo"}}`
	resp, err := sc.Post("http://localhost/graphql", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unscoped mutation should be denied, got %d", resp.StatusCode)
	}
}

// Regression for FINDING 2 (CRITICAL): a node-ID mutation is authorized against the
// repository GitHub says the node belongs to — not one inferred from a read. Here the
// node resolves authoritatively to blocked-org/secret, so the mutation is denied even
// though the client has write on allowed-org/rw-repo.
func TestSec_MutationResolvesToRealRepoAndDenies(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret)

	body := `{"query":"mutation($id: ID!){ closePullRequest(input:{pullRequestId:$id}){ clientMutationId } }","variables":{"id":"PR_BlockedSecretNode"}}`
	resp, err := client.Post(env.gheServer.URL+"/api/graphql", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("mutation on a node owned by blocked-org/secret must be denied, got %d", resp.StatusCode)
	}
}

// Control: a node that authoritatively resolves to the client's writable repo is allowed.
func TestSec_MutationResolvesToAllowedRepo(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret)

	body := `{"query":"mutation($id: ID!){ closePullRequest(input:{pullRequestId:$id}){ clientMutationId } }","variables":{"id":"PR_AllowedRwNode"}}`
	resp, err := client.Post(env.gheServer.URL+"/api/graphql", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		t.Fatalf("mutation on a node owned by allowed-org/rw-repo should be allowed, got 403")
	}
}

func TestSec_GHEAuthEndpointLeaksUserInfo(t *testing.T) {
	env := setup(t)

	restrictedPol := policy.Policy{
		Defaults: policy.Defaults{Mode: policy.ModeDeny},
	}
	_, secret, _ := env.store.Create("no-access-token", restrictedPol)
	client := gheClient(secret)

	resp, err := client.Get(env.gheServer.URL + "/api/v3/user")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 (synthetic response), got %d", resp.StatusCode)
	}
	var user map[string]any
	json.Unmarshal(body, &user)
	if user["login"] != "bgh-proxy" {
		t.Fatalf("expected synthetic login=bgh-proxy, got %v", user["login"])
	}
}

func TestSec_MutationWithDummyRepoScope(t *testing.T) {
	env := setupWithPerms(t)
	client := gheClient(env.secret)

	body := `{
		"query": "mutation($owner: String!, $name: String!) { repository(owner: $owner, name: $name) { id } mergePullRequest(input: {pullRequestId: \"PR_fromDeniedRepo\"}) { pullRequest { url } } }",
		"variables": {"owner": "allowed-org", "name": "rw-repo"}
	}`
	resp, err := client.Post(
		env.gheServer.URL+"/api/graphql",
		"application/json",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("mutation with dummy repo scope should be denied (unscoped write), got %d", resp.StatusCode)
	}
}

func TestSec_ErrorMessageLeaksPolicy(t *testing.T) {
	env := setup(t)
	client := gheClient(env.secret)

	resp, err := client.Get(env.gheServer.URL + "/api/v3/repos/blocked-org/secret/pulls")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	bodyStr := string(body)
	if strings.Contains(bodyStr, "blocked-org/secret") ||
		strings.Contains(bodyStr, "none") ||
		strings.Contains(bodyStr, "policy") {
		t.Fatalf("error message leaks policy details: %s", strings.TrimSpace(bodyStr))
	}
}

func TestNodeCacheMissDenied(t *testing.T) {
	env := setup(t)
	client := socketClient(env.socketPath)

	mutationBody := `{"query":"mutation { mergePullRequest(input: {pullRequestId: $id}) { pullRequest { url } } }","variables":{"input":{"pullRequestId":"PR_notInCache"}}}`
	resp, err := client.Post("http://localhost/graphql", "application/json", strings.NewReader(mutationBody))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("mutation with uncached ID should be denied, got %d", resp.StatusCode)
	}
}
