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
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"login": "testuser"})
	})
	mux.HandleFunc("POST /graphql", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bodyStr := string(body)
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

func setup(t *testing.T) *testEnv {
	t.Helper()

	mock := mockGitHub()

	tmpDir := t.TempDir()
	auditPath := filepath.Join(tmpDir, "audit.jsonl")
	socketPath := filepath.Join("/tmp", fmt.Sprintf("bgh-test-%d.sock", os.Getpid()))

	tokenStore, secret := testStore(t, tmpDir)
	auditLogger := audit.NewLogger(auditPath)

	transport := &http.Transport{}
	client := &http.Client{Transport: transport}

	nodeCache := nodecache.New(30 * time.Minute)

	gheHandler := &Handler{
		GithubToken: "fake-gh-token",
		Store:       tokenStore,
		Audit:       auditLogger,
		AdminSecret: "admin-secret",
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
		AdminSecret:  "admin-secret",
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
