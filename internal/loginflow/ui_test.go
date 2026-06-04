package loginflow

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"

	"better-gh/internal/store"
)

// cdo issues a request with a cookie-carrying client (so the owner session cookie persists)
// and returns the status and raw body (which may be a JSON object or array).
func cdo(t *testing.T, c *http.Client, method, url string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func obj(raw []byte) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}
func arr(raw []byte) []any {
	var a []any
	_ = json.Unmarshal(raw, &a)
	return a
}

// signInClient runs the standalone GitHub sign-in and returns a client carrying the owner
// session cookie, ready to drive the console's management endpoints.
func signInClient(t *testing.T, innerToken, preOwner string) (*httptest.Server, *store.Store, *http.Client) {
	t.Helper()
	srv, st := newServerOnly(t, innerToken, preOwner)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	// Start via the cookie-carrying client so the grant-binding cookie (audit F2) is captured and
	// later presented at /ui/api/session — only the starting browser can mint the owner session.
	code, raw := cdo(t, c, "POST", srv.URL+"/ui/api/start", map[string]string{})
	if code != http.StatusOK {
		t.Fatalf("start failed (%d): %s", code, raw)
	}
	grantID, _ := obj(raw)["grant_id"].(string)
	if grantID == "" {
		t.Fatalf("start gave no grant_id: %s", raw)
	}
	waitStatus(t, srv, "/ui/api/poll", grantID)
	code, raw = cdo(t, c, "POST", srv.URL+"/ui/api/session", map[string]string{"grant_id": grantID})
	if code != http.StatusOK {
		t.Fatalf("session failed (%d): %s", code, raw)
	}
	return srv, st, c
}

// Full console happy path: sign in, prefill account, then create / list / revoke a token.
func TestConsole_CreateListRevoke(t *testing.T) {
	srv, st, c := signInClient(t, "tok-alice", "") // first sign-in claims alice

	// The page is served.
	resp, err := http.Get(srv.URL + "/ui")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /ui = %d", resp.StatusCode)
	}

	// Account prefetch: login + repos + orgs (own login offered first as an org target).
	code, raw := cdo(t, c, "GET", srv.URL+"/ui/api/account", nil)
	if code != http.StatusOK {
		t.Fatalf("account (%d): %s", code, raw)
	}
	acc := obj(raw)
	if acc["login"] != "alice" {
		t.Fatalf("account login = %v", acc["login"])
	}
	if len(acc["repos"].([]any)) != 2 {
		t.Fatalf("expected 2 repos, got %v", acc["repos"])
	}
	orgs := acc["orgs"].([]any)
	if len(orgs) != 2 || orgs[0] != "alice" || orgs[1] != "alice-org" {
		t.Fatalf("orgs = %v (want [alice alice-org])", orgs)
	}

	// No tokens yet.
	_, raw = cdo(t, c, "GET", srv.URL+"/ui/api/tokens", nil)
	if n := len(arr(raw)); n != 0 {
		t.Fatalf("expected 0 tokens, got %d", n)
	}

	// Create one via the builder policy.
	pol := map[string]any{"defaults": map[string]any{"mode": "deny"}, "repo": []map[string]string{{"name": "alice/app", "access": "read"}}}
	code, raw = cdo(t, c, "POST", srv.URL+"/ui/api/tokens", map[string]any{"name": "laptop", "policy": pol})
	if code != http.StatusOK {
		t.Fatalf("create (%d): %s", code, raw)
	}
	secret, _ := obj(raw)["secret"].(string)
	if secret == "" {
		t.Fatalf("create returned no secret: %s", raw)
	}
	tok := st.Lookup(secret)
	if tok == nil || tok.Name != "laptop" {
		t.Fatalf("minted token not in store: %+v", tok)
	}
	if len(tok.Policy.Repo) != 1 || !strings.EqualFold(tok.Policy.Repo[0].Name, "alice/app") {
		t.Fatalf("policy not applied: %+v", tok.Policy)
	}

	// It shows up in the list.
	_, raw = cdo(t, c, "GET", srv.URL+"/ui/api/tokens", nil)
	list := arr(raw)
	if len(list) != 1 {
		t.Fatalf("expected 1 token, got %d", len(list))
	}
	id, _ := list[0].(map[string]any)["id"].(string)

	// Revoke it → secret stops resolving.
	code, _ = cdo(t, c, "DELETE", srv.URL+"/ui/api/tokens/"+id, nil)
	if code != http.StatusOK {
		t.Fatalf("revoke = %d", code)
	}
	if st.Lookup(secret) != nil {
		t.Fatal("revoked secret still resolves")
	}
}

// A token can be created from a pasted TOML spec, and user/meta are auto-granted.
func TestConsole_CreateFromTOML(t *testing.T) {
	srv, st, c := signInClient(t, "tok-alice", "")
	spec := "[defaults]\nmode = \"deny\"\n\n[[repo]]\nname = \"alice/app\"\naccess = \"read-write\"\n"
	code, raw := cdo(t, c, "POST", srv.URL+"/ui/api/tokens", map[string]any{"name": "from-toml", "spec_toml": spec})
	if code != http.StatusOK {
		t.Fatalf("create from toml (%d): %s", code, raw)
	}
	tok := st.Lookup(obj(raw)["secret"].(string))
	if tok == nil {
		t.Fatal("toml token not in store")
	}
	if len(tok.Policy.Repo) != 1 || !strings.EqualFold(tok.Policy.Repo[0].Name, "alice/app") {
		t.Fatalf("toml policy not parsed: %+v", tok.Policy)
	}
	if tok.Policy.Defaults.Unscoped["user"] == 0 || tok.Policy.Defaults.Unscoped["meta"] == 0 {
		t.Fatalf("user/meta not auto-granted: %+v", tok.Policy.Defaults.Unscoped)
	}

	// Malformed TOML is rejected.
	code, _ = cdo(t, c, "POST", srv.URL+"/ui/api/tokens", map[string]any{"spec_toml": "this is not = [valid toml"})
	if code != http.StatusBadRequest {
		t.Fatalf("malformed toml should be 400, got %d", code)
	}
}

// Editing re-issues: a replace_id mints a new secret and revokes the old one.
func TestConsole_EditReissues(t *testing.T) {
	srv, st, c := signInClient(t, "tok-alice", "")
	_, raw := cdo(t, c, "POST", srv.URL+"/ui/api/tokens", map[string]any{"name": "edit-me", "policy": map[string]any{"defaults": map[string]any{"mode": "deny"}}})
	a := obj(raw)
	secretA, idA := a["secret"].(string), a["id"].(string)
	if st.Lookup(secretA) == nil {
		t.Fatal("first token missing")
	}

	_, raw = cdo(t, c, "POST", srv.URL+"/ui/api/tokens", map[string]any{
		"name": "edit-me", "replace_id": idA,
		"policy": map[string]any{"defaults": map[string]any{"mode": "deny"}, "repo": []map[string]string{{"name": "alice/app", "access": "read"}}},
	})
	secretB := obj(raw)["secret"].(string)
	if st.Lookup(secretA) != nil {
		t.Fatal("old secret still resolves after re-issue")
	}
	if st.Lookup(secretB) == nil {
		t.Fatal("re-issued secret does not resolve")
	}
}

// The TOML parse endpoint (used by the Builder↔TOML tab swap) parses valid specs, rejects
// malformed ones, and requires a session.
func TestConsole_ParsePolicy(t *testing.T) {
	srv, _, c := signInClient(t, "tok-alice", "")
	code, raw := cdo(t, c, "POST", srv.URL+"/ui/api/policy/parse",
		map[string]string{"spec_toml": "[defaults]\nmode=\"deny\"\n[[repo]]\nname=\"alice/app\"\naccess=\"read\""})
	if code != http.StatusOK {
		t.Fatalf("parse (%d): %s", code, raw)
	}
	pol, _ := obj(raw)["policy"].(map[string]any)
	if repos, _ := pol["repo"].([]any); len(repos) != 1 {
		t.Fatalf("expected 1 parsed repo, got %v", pol["repo"])
	}
	if code, _ := cdo(t, c, "POST", srv.URL+"/ui/api/policy/parse", map[string]string{"spec_toml": "bad = [unterminated"}); code != http.StatusBadRequest {
		t.Fatalf("malformed TOML should be 400, got %d", code)
	}
	jar, _ := cookiejar.New(nil)
	if code, _ := cdo(t, &http.Client{Jar: jar}, "POST", srv.URL+"/ui/api/policy/parse", map[string]string{"spec_toml": "x"}); code != http.StatusUnauthorized {
		t.Fatalf("parse without session should be 401, got %d", code)
	}
}

// Every management endpoint requires a valid owner session.
func TestConsole_RequiresSession(t *testing.T) {
	srv, _ := newServerOnly(t, "tok-alice", "")
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar} // no session established
	for _, ep := range []struct{ m, p string }{
		{"GET", "/ui/api/account"}, {"GET", "/ui/api/tokens"},
		{"POST", "/ui/api/tokens"}, {"DELETE", "/ui/api/tokens/whatever"},
	} {
		if code, _ := cdo(t, c, ep.m, srv.URL+ep.p, nil); code != http.StatusUnauthorized {
			t.Fatalf("%s %s without session = %d, want 401", ep.m, ep.p, code)
		}
	}
}

// A non-owner sign-in cannot obtain a session and therefore cannot manage tokens.
func TestConsole_NonOwnerDenied(t *testing.T) {
	srv, st := newServerOnly(t, "tok-bob", "alice") // claimed by alice; bob signs in
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}

	_, s := post(t, srv, "/ui/api/start", map[string]string{})
	grantID := s["grant_id"].(string)
	if p := waitStatus(t, srv, "/ui/api/poll", grantID); p["status"] != "denied" {
		t.Fatalf("bob must be denied, got %v", p)
	}
	if code, _ := cdo(t, c, "POST", srv.URL+"/ui/api/session", map[string]string{"grant_id": grantID}); code != http.StatusForbidden {
		t.Fatalf("session on a denied grant should be 403, got %d", code)
	}
	if code, _ := cdo(t, c, "GET", srv.URL+"/ui/api/tokens", nil); code != http.StatusUnauthorized {
		t.Fatalf("tokens without session should be 401, got %d", code)
	}
	if len(st.List()) != 0 {
		t.Fatalf("a token was minted for a non-owner: %d", len(st.List()))
	}
}

// TestConsole_GrantHijackRequiresBindingCookie is the audit F2 regression: a party who learns a
// grant_id (or user_code) but lacks the browser-binding cookie cannot turn an authenticated grant
// into an owner session or an arbitrary-policy token. Only the starting browser can.
func TestConsole_GrantHijackRequiresBindingCookie(t *testing.T) {
	srv, st := newServerOnly(t, "tok-alice", "")

	// Browser A starts and authenticates (holds the binding cookie in its jar).
	jarA, _ := cookiejar.New(nil)
	a := &http.Client{Jar: jarA}
	code, raw := cdo(t, a, "POST", srv.URL+"/ui/api/start", map[string]string{})
	if code != http.StatusOK {
		t.Fatalf("start: %d %s", code, raw)
	}
	grantID := obj(raw)["grant_id"].(string)
	waitStatus(t, srv, "/ui/api/poll", grantID)

	// Attacker B has the grant_id but no binding cookie.
	b := &http.Client{}
	if code, _ := cdo(t, b, "POST", srv.URL+"/ui/api/session", map[string]string{"grant_id": grantID}); code != http.StatusForbidden {
		t.Fatalf("session without binding cookie must be 403, got %d", code)
	}
	if code, _ := cdo(t, b, "POST", srv.URL+"/login/api/approve",
		map[string]any{"grant_id": grantID, "policy": map[string]any{"defaults": map[string]any{"mode": "allow"}}}); code != http.StatusForbidden {
		t.Fatalf("approve without binding cookie must be 403, got %d", code)
	}
	if len(st.List()) != 0 {
		t.Fatalf("attacker minted a token without the binding cookie: %d", len(st.List()))
	}

	// Browser A (with the cookie) can still complete the session.
	if code, raw := cdo(t, a, "POST", srv.URL+"/ui/api/session", map[string]string{"grant_id": grantID}); code != http.StatusOK {
		t.Fatalf("legit browser session failed (%d): %s", code, raw)
	}
}
