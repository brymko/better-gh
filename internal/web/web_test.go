package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"better-gh/internal/policy"
	"better-gh/internal/store"
)

func testHandler(t *testing.T) (*Handler, *store.Store) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	return NewHandler(s, "admin-secret"), s
}

func adminReq(method, path, body string) *http.Request {
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	var req *http.Request
	if reader != nil {
		req = httptest.NewRequest(method, path, reader)
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.Header.Set("Authorization", "token admin-secret")
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestCreateTokenBasic(t *testing.T) {
	h, _ := testHandler(t)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, adminReq("POST", "/api/tokens", `{
		"name": "test-token",
		"policy": {
			"default": "deny",
			"org": [{"name": "my-org", "access": "read"}],
			"repo": [{"name": "my-org/repo", "access": "read-write"}]
		}
	}`))

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["name"] != "test-token" {
		t.Fatalf("expected name=test-token, got %s", resp["name"])
	}
	if resp["secret"] == "" {
		t.Fatal("expected non-empty secret")
	}
	if resp["id"] == "" {
		t.Fatal("expected non-empty id")
	}
}

func TestCreateTokenWithPermissions(t *testing.T) {
	h, s := testHandler(t)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, adminReq("POST", "/api/tokens", `{
		"name": "perm-token",
		"policy": {
			"default": "deny",
			"org": [{"name": "org", "access": "read", "permissions": {"pulls": "read-write"}}],
			"repo": [{"name": "org/repo", "access": "read", "permissions": {"actions": "none", "issues": "read-write"}}]
		}
	}`))

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	tokens := s.List()
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}

	tok := tokens[0]
	if len(tok.Policy.Repo) != 1 {
		t.Fatal("expected 1 repo rule")
	}
	if tok.Policy.Repo[0].Permissions["actions"] != policy.AccessNone {
		t.Fatal("expected repo actions=none")
	}
	if tok.Policy.Repo[0].Permissions["issues"] != policy.AccessReadWrite {
		t.Fatal("expected repo issues=read-write")
	}
	if len(tok.Policy.Org) != 1 {
		t.Fatal("expected 1 org rule")
	}
	if tok.Policy.Org[0].Permissions["pulls"] != policy.AccessReadWrite {
		t.Fatal("expected org pulls=read-write")
	}
}

func TestCreateTokenWithUnscoped(t *testing.T) {
	h, s := testHandler(t)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, adminReq("POST", "/api/tokens", `{
		"name": "unscoped-token",
		"policy": {
			"default": "deny",
			"unscoped": {"user": "read", "search": "read", "gists": "read-write"},
			"org": [],
			"repo": []
		}
	}`))

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	tokens := s.List()
	tok := tokens[0]
	if len(tok.Policy.Defaults.Unscoped) != 3 {
		t.Fatalf("expected 3 unscoped entries, got %d", len(tok.Policy.Defaults.Unscoped))
	}
	if tok.Policy.Defaults.Unscoped["user"] != policy.AccessRead {
		t.Fatal("expected user=read")
	}
	if tok.Policy.Defaults.Unscoped["gists"] != policy.AccessReadWrite {
		t.Fatal("expected gists=read-write")
	}
}

func TestCreateTokenMissingName(t *testing.T) {
	h, _ := testHandler(t)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, adminReq("POST", "/api/tokens", `{
		"name": "",
		"policy": {"default": "deny"}
	}`))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestCreateTokenInvalidAccess(t *testing.T) {
	h, _ := testHandler(t)

	tests := []struct {
		name string
		body string
	}{
		{"invalid default", `{"name":"t","policy":{"default":"invalid"}}`},
		{"invalid repo access", `{"name":"t","policy":{"default":"deny","repo":[{"name":"o/r","access":"invalid"}]}}`},
		{"invalid org access", `{"name":"t","policy":{"default":"deny","org":[{"name":"o","access":"invalid"}]}}`},
		{"invalid repo perm", `{"name":"t","policy":{"default":"deny","repo":[{"name":"o/r","access":"read","permissions":{"pulls":"invalid"}}]}}`},
		{"invalid org perm", `{"name":"t","policy":{"default":"deny","org":[{"name":"o","access":"read","permissions":{"pulls":"invalid"}}]}}`},
		{"invalid unscoped", `{"name":"t","policy":{"default":"deny","unscoped":{"user":"invalid"}}}`},
	}

	for _, tt := range tests {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, adminReq("POST", "/api/tokens", tt.body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d: %s", tt.name, w.Code, w.Body.String())
		}
	}
}

func TestCreateTokenInvalidJSON(t *testing.T) {
	h, _ := testHandler(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, adminReq("POST", "/api/tokens", "not json"))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestListTokens(t *testing.T) {
	h, s := testHandler(t)

	pol := policy.Policy{Defaults: policy.Defaults{Mode: policy.ModeDeny}}
	s.Create("tok-a", pol)
	s.Create("tok-b", pol)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, adminReq("GET", "/api/tokens", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var tokens []map[string]any
	json.Unmarshal(w.Body.Bytes(), &tokens)
	if len(tokens) != 2 {
		t.Fatalf("expected 2 tokens, got %d", len(tokens))
	}
}

func TestGetToken(t *testing.T) {
	h, s := testHandler(t)

	pol := policy.Policy{
		Defaults: policy.Defaults{
			Mode: policy.ModeDeny,
			Unscoped: map[string]policy.Access{
				"user": policy.AccessRead,
			},
		},
		Repo: []policy.RepoRule{{
			Name:   "org/repo",
			Access: policy.AccessRead,
			Permissions: map[string]policy.Access{
				"pulls": policy.AccessReadWrite,
			},
		}},
	}
	tok, _, _ := s.Create("detail-token", pol)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, adminReq("GET", "/api/tokens/"+tok.ID, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp store.ProxyToken
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Name != "detail-token" {
		t.Fatalf("expected name=detail-token, got %s", resp.Name)
	}
	if resp.Policy.Defaults.Unscoped["user"] != policy.AccessRead {
		t.Fatal("expected unscoped user=read in response")
	}
	if resp.Policy.Repo[0].Permissions["pulls"] != policy.AccessReadWrite {
		t.Fatal("expected repo pulls=read-write in response")
	}
}

func TestGetTokenNotFound(t *testing.T) {
	h, _ := testHandler(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, adminReq("GET", "/api/tokens/nonexistent", ""))
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestRevokeToken(t *testing.T) {
	h, s := testHandler(t)

	pol := policy.Policy{Defaults: policy.Defaults{Mode: policy.ModeDeny}}
	tok, _, _ := s.Create("revoke-me", pol)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, adminReq("DELETE", "/api/tokens/"+tok.ID, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	revoked := s.Get(tok.ID)
	if revoked == nil || !revoked.Revoked {
		t.Fatal("token should be revoked")
	}
}

func TestRevokeTokenNotFound(t *testing.T) {
	h, _ := testHandler(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, adminReq("DELETE", "/api/tokens/nonexistent", ""))
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

// Regression for the token-delete revocation bypass: `?hard=true` removes the entry
// through the running server's store (so the CLI no longer mutates the file out of
// band, which the server would overwrite). Soft revoke marks it; hard delete removes it.
func TestSec_HardDeleteThroughServerStore(t *testing.T) {
	h, s := testHandler(t)

	_, secret, err := s.Create("doomed", policy.Policy{Defaults: policy.Defaults{Mode: policy.ModeDeny}})
	if err != nil {
		t.Fatal(err)
	}
	id := s.Lookup(secret).ID

	w := httptest.NewRecorder()
	h.ServeHTTP(w, adminReq("DELETE", "/api/tokens/"+id+"?hard=true", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if s.Get(id) != nil {
		t.Fatalf("token should be removed from the live store, still present")
	}
	if s.Lookup(secret) != nil {
		t.Fatalf("deleted token secret should no longer authenticate")
	}
}

func TestUnauthorizedAccess(t *testing.T) {
	h, _ := testHandler(t)

	noAuth := httptest.NewRequest("GET", "/api/tokens", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, noAuth)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", w.Code)
	}

	wrongAuth := httptest.NewRequest("GET", "/api/tokens", nil)
	wrongAuth.Header.Set("Authorization", "token wrong-secret")
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, wrongAuth)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with wrong auth, got %d", w2.Code)
	}
}

func TestListTokensWithLastUsed(t *testing.T) {
	h, s := testHandler(t)

	pol := policy.Policy{Defaults: policy.Defaults{Mode: policy.ModeDeny}}
	tok, _, _ := s.Create("used-token", pol)

	s.TouchLastUsed(tok.ID)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, adminReq("GET", "/api/tokens", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var tokens []map[string]any
	json.Unmarshal(w.Body.Bytes(), &tokens)
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}
	lastUsed, ok := tokens[0]["last_used"].(string)
	if !ok || lastUsed == "" {
		t.Fatal("expected non-empty last_used in response")
	}
}

func TestListTokensWithRevokedToken(t *testing.T) {
	h, s := testHandler(t)

	pol := policy.Policy{Defaults: policy.Defaults{Mode: policy.ModeDeny}}
	tok, _, _ := s.Create("revoke-me", pol)
	s.Revoke(tok.ID)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, adminReq("GET", "/api/tokens", ""))

	var tokens []map[string]any
	json.Unmarshal(w.Body.Bytes(), &tokens)
	if len(tokens) != 1 {
		t.Fatalf("expected 1 token, got %d", len(tokens))
	}
	if tokens[0]["revoked"] != true {
		t.Fatal("expected revoked=true in list response")
	}
}

func TestCreateTokenWhitespaceOnlyName(t *testing.T) {
	h, _ := testHandler(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, adminReq("POST", "/api/tokens", `{
		"name": "   ",
		"policy": {"default": "deny"}
	}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("whitespace-only name should be rejected, got %d", w.Code)
	}
}

// --- Security audit tests ---

func TestSec_AdminSecretInQueryParamLeaks(t *testing.T) {
	h, _ := testHandler(t)

	req := httptest.NewRequest("GET", "/api/tokens?token=admin-secret", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("query param auth should be rejected, got %d", w.Code)
	}
}

func TestSec_WrongQueryParamTokenDenied(t *testing.T) {
	h, _ := testHandler(t)
	req := httptest.NewRequest("GET", "/api/tokens?token=wrong-secret", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong query param token should be denied, got %d", w.Code)
	}
}

func TestCreateTokenDefaultModeEmpty(t *testing.T) {
	h, s := testHandler(t)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, adminReq("POST", "/api/tokens", `{
		"name": "default-deny",
		"policy": {"org": [], "repo": []}
	}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	tok := s.List()[0]
	if tok.Policy.Defaults.Mode != policy.ModeDeny {
		t.Fatal("empty default should default to deny")
	}
}
