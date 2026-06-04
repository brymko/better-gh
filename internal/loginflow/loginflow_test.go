package loginflow

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"better-gh/internal/owner"
	"better-gh/internal/store"
)

// mockGitHub stands in for github.com + api.github.com: the device-flow endpoints and a
// GraphQL viewer{login} that derives the login from the bearer token ("tok-alice" -> alice).
func mockGitHub(t *testing.T, accessToken string) *httptest.Server {
	t.Helper()
	m := http.NewServeMux()
	m.HandleFunc("/login/device/code", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"device_code":"GH_DEVICE","user_code":"WXYZ-1234","verification_uri":"https://github.com/login/device","interval":0,"expires_in":900}`)
	})
	m.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"`+accessToken+`","token_type":"bearer","scope":"read:user"}`)
	})
	m.HandleFunc("/graphql", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "bearer ")
		login := strings.TrimPrefix(tok, "tok-")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"data":{"viewer":{"login":"`+login+`"}}}`)
	})
	// For the console's account prefetch (fetched with the captured custodian token).
	m.HandleFunc("/user/repos", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `[{"full_name":"alice/app","private":false},{"full_name":"alice/secret","private":true}]`)
	})
	m.HandleFunc("/user/orgs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `[{"login":"alice-org"}]`)
	})
	s := httptest.NewServer(m)
	t.Cleanup(s.Close)
	return s
}

// newTestHandler builds a loginflow against a mock GitHub. preOwner, if set, pre-claims the
// deployment for that login so a *different* sign-in can be tested as a non-owner; empty
// means unclaimed, so the first sign-in claims it (TOFU).
func newTestHandler(t *testing.T, innerToken, preOwner string) (*Handler, *store.Store, *httptest.Server) {
	t.Helper()
	gh := mockGitHub(t, innerToken)
	st, err := store.Open(t.TempDir() + "/tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	ow, err := owner.Open(t.TempDir()+"/owner.json", "")
	if err != nil {
		t.Fatal(err)
	}
	if preOwner != "" {
		if _, _, err := ow.SignIn(preOwner, "tok-"+preOwner); err != nil {
			t.Fatal(err)
		}
	}
	h := NewHandler(&Handler{
		Store: st, Owner: ow, OAuthClientID: "x",
		GitHubBaseURL: gh.URL, APIBaseURL: gh.URL, HTTPClient: &http.Client{},
	})
	t.Cleanup(h.Stop)
	return h, st, httptest.NewServer(h)
}

func post(t *testing.T, srv *httptest.Server, path string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// postc POSTs JSON with a cookie-carrying client, so the grant-binding cookie (audit F2) set on
// begin/authorize persists through approve — modelling the single browser that drives the flow.
func postc(t *testing.T, c *http.Client, srv *httptest.Server, path string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// browserClient returns an http.Client with a cookie jar (one "browser") for driving a sign-in.
func browserClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar}
}

func postForm(t *testing.T, srv *httptest.Server, path string, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(srv.URL+path, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// waitStatus polls a grant-status endpoint until the sign-in settles (status != "pending") or
// times out. The sign-in runs in a background goroutine (runGitHubAuth drives GitHub's device
// flow), so callers wait for the result exactly as the real page does.
func waitStatus(t *testing.T, srv *httptest.Server, path, grantID string) map[string]any {
	t.Helper()
	for i := 0; i < 250; i++ {
		_, p := post(t, srv, path, map[string]string{"grant_id": grantID})
		if p["status"] != "pending" {
			return p
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("grant %q did not settle (still pending)", grantID)
	return nil
}

// Full device-flow happy path: gh gets a device code, operator authenticates as the custodian
// owner via GitHub, picks a policy, and gh's access_token poll returns a working bgh_ token.
func TestDeviceFlow_HappyPath(t *testing.T) {
	srv, st := newServerOnly(t, "tok-alice", "")

	_, dc := postForm(t, srv, "/login/device/code", url.Values{"client_id": {"x"}, "scope": {"repo"}})
	deviceCode, _ := dc["device_code"].(string)
	userCode, _ := dc["user_code"].(string)
	if deviceCode == "" || userCode == "" {
		t.Fatalf("device/code missing fields: %v", dc)
	}

	// Before authorization, gh's poll must say pending.
	_, at := postForm(t, srv, "/login/oauth/access_token", url.Values{"device_code": {deviceCode}})
	if at["error"] != "authorization_pending" {
		t.Fatalf("expected authorization_pending, got %v", at)
	}

	// Operator begins GitHub auth (in their browser — the binding cookie is set here, audit F2).
	browser := browserClient(t)
	_, b := postc(t, browser, srv, "/login/api/begin", map[string]string{"user_code": userCode})
	grantID, _ := b["grant_id"].(string)
	if grantID == "" || b["github_user_code"] == nil {
		t.Fatalf("begin missing grant_id/github_user_code: %v", b)
	}

	// Poll (background goroutine drives GitHub): tok-alice == owner -> authenticated.
	p := waitStatus(t, srv, "/login/api/poll", grantID)
	if p["status"] != "authenticated" || p["login"] != "alice" {
		t.Fatalf("expected authenticated as alice, got %v", p)
	}

	// Approve with a scoped policy — from the SAME browser (cookie carries the grant binding).
	pol := map[string]any{"defaults": map[string]any{"mode": "deny"}, "repo": []map[string]string{{"name": "alice/app", "access": "read"}}}
	code, ap := postc(t, browser, srv, "/login/api/approve", map[string]any{"grant_id": grantID, "name": "laptop", "policy": pol})
	if code != http.StatusOK || ap["status"] != "approved" {
		t.Fatalf("approve failed (%d): %v", code, ap)
	}

	// gh's poll now returns the minted token.
	_, at2 := postForm(t, srv, "/login/oauth/access_token", url.Values{"device_code": {deviceCode}})
	secret, _ := at2["access_token"].(string)
	if secret == "" {
		t.Fatalf("expected access_token, got %v", at2)
	}

	// The secret must resolve to a usable, correctly-scoped proxy token.
	tok := st.Lookup(secret)
	if tok == nil {
		t.Fatal("minted secret does not resolve in the store")
	}
	if tok.Name != "laptop" {
		t.Fatalf("token name = %q, want laptop", tok.Name)
	}
	if len(tok.Policy.Repo) != 1 || !strings.EqualFold(tok.Policy.Repo[0].Name, "alice/app") {
		t.Fatalf("policy not applied: %+v", tok.Policy)
	}
	// ensureLoginUsable floor: user + meta must be readable so gh works.
	if tok.Policy.Defaults.Unscoped["user"] == 0 || tok.Policy.Defaults.Unscoped["meta"] == 0 {
		t.Fatalf("user/meta not granted: %+v", tok.Policy.Defaults.Unscoped)
	}

	// One-time issuance: a replayed exchange must not re-yield the secret.
	_, at3 := postForm(t, srv, "/login/oauth/access_token", url.Values{"device_code": {deviceCode}})
	if at3["error"] != "expired_token" {
		t.Fatalf("replayed exchange should be expired_token, got %v", at3)
	}
}

// The identity gate: a GitHub login that is NOT the custodian owner must be denied and must
// not be able to mint anything.
func TestIdentityGate_NonOwnerDenied(t *testing.T) {
	srv, st := newServerOnly(t, "tok-bob", "alice") // deployment pre-claimed by alice

	_, dc := postForm(t, srv, "/login/device/code", url.Values{"client_id": {"x"}})
	userCode := dc["user_code"].(string)
	_, b := post(t, srv, "/login/api/begin", map[string]string{"user_code": userCode})
	grantID := b["grant_id"].(string)

	p := waitStatus(t, srv, "/login/api/poll", grantID)
	if p["status"] != "denied" {
		t.Fatalf("non-owner must be denied, got %v", p)
	}

	// Approve must be refused for a denied/unauthenticated grant.
	code, _ := post(t, srv, "/login/api/approve", map[string]any{"grant_id": grantID, "policy": map[string]any{}})
	if code != http.StatusConflict {
		t.Fatalf("approve on denied grant should be 409, got %d", code)
	}
	// gh's poll must report access_denied, and nothing was minted.
	_, at := postForm(t, srv, "/login/oauth/access_token", url.Values{"device_code": {dc["device_code"].(string)}})
	if at["error"] != "access_denied" {
		t.Fatalf("expected access_denied, got %v", at)
	}
	if len(st.List()) != 0 {
		t.Fatalf("a token was minted for a non-owner: %d tokens", len(st.List()))
	}
}

// Round-12 audit H6: a non-loopback redirect_uri (token-exfiltration vector) is rejected at the
// authorize page, while gh's real loopback callback is accepted.
func TestWebFlow_RejectsNonLoopbackRedirect(t *testing.T) {
	srv, _ := newServerOnly(t, "tok-alice", "")
	bad := []string{
		"https://evil.example/cb",
		"http://attacker.test/x",
		"http://169.254.169.254/", // link-local, not loopback
		"ftp://127.0.0.1/",        // wrong scheme
	}
	for _, rd := range bad {
		resp, err := http.Get(srv.URL + "/login/oauth/authorize?client_id=x&state=s&redirect_uri=" + url.QueryEscape(rd))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("redirect_uri %q should be rejected 400, got %d", rd, resp.StatusCode)
		}
	}
	for _, ok := range []string{"http://127.0.0.1:9999/callback", "http://localhost:8080/cb", "http://[::1]:7000/"} {
		resp, err := http.Get(srv.URL + "/login/oauth/authorize?client_id=x&state=s&redirect_uri=" + url.QueryEscape(ok))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("loopback redirect_uri %q should be accepted, got %d", ok, resp.StatusCode)
		}
	}
}

// Web (browser) flow: authorize page is bound to gh's state; approval returns a redirect with
// an auth code that gh exchanges for the token.
func TestWebFlow_HappyPath(t *testing.T) {
	srv, st := newServerOnly(t, "tok-alice", "")

	// gh opens the authorize page with state + redirect_uri (in the operator's browser — the
	// binding cookie is set on this response, audit F2).
	browser := browserClient(t)
	state := "st123"
	redirect := "http://127.0.0.1:9999/callback"
	resp, err := browser.Get(srv.URL + "/login/oauth/authorize?client_id=x&state=" + state + "&redirect_uri=" + url.QueryEscape(redirect))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize page status %d", resp.StatusCode)
	}

	_, b := postc(t, browser, srv, "/login/api/begin", map[string]string{"state": state})
	grantID := b["grant_id"].(string)
	if p := waitStatus(t, srv, "/login/api/poll", grantID); p["status"] != "authenticated" {
		t.Fatalf("expected authenticated, got %v", p)
	}

	pol := map[string]any{"defaults": map[string]any{"mode": "deny"}}
	_, ap := postc(t, browser, srv, "/login/api/approve", map[string]any{"grant_id": grantID, "policy": pol})
	red, _ := ap["redirect"].(string)
	if !strings.HasPrefix(red, redirect) || !strings.Contains(red, "state="+state) {
		t.Fatalf("bad redirect: %q", red)
	}
	// Extract the auth code gh would, and exchange it.
	u, _ := url.Parse(red)
	authCode := u.Query().Get("code")
	if authCode == "" {
		t.Fatalf("no auth code in redirect %q", red)
	}
	_, at := postForm(t, srv, "/login/oauth/access_token", url.Values{"code": {authCode}, "redirect_uri": {redirect}})
	secret, _ := at["access_token"].(string)
	if secret == "" || st.Lookup(secret) == nil {
		t.Fatalf("web flow did not yield a usable token: %v", at)
	}
}

// Behind a TLS-terminating front, the device-flow verification_uri must point at the public
// ExternalURL, not the backend Host the front forwards to.
func TestDeviceFlow_VerificationURIUsesExternalURL(t *testing.T) {
	gh := mockGitHub(t, "tok-alice")
	st, err := store.Open(t.TempDir() + "/tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	ow, err := owner.Open(t.TempDir()+"/owner.json", "")
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(&Handler{
		Store: st, Owner: ow, OAuthClientID: "x",
		GitHubBaseURL: gh.URL, APIBaseURL: gh.URL, HTTPClient: &http.Client{},
		ExternalURL: "https://vps.tailnet.ts.net/", // trailing slash should be trimmed
	})
	t.Cleanup(h.Stop)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	_, dc := postForm(t, srv, "/login/device/code", url.Values{"client_id": {"x"}})
	want := "https://vps.tailnet.ts.net/login/device"
	if dc["verification_uri"] != want {
		t.Fatalf("verification_uri = %v, want %q", dc["verification_uri"], want)
	}
	if vc, _ := dc["verification_uri_complete"].(string); !strings.HasPrefix(vc, want+"?user_code=") {
		t.Fatalf("verification_uri_complete = %q, want prefix %q", vc, want+"?user_code=")
	}
}

func newServerOnly(t *testing.T, innerToken, preOwner string) (*httptest.Server, *store.Store) {
	t.Helper()
	_, st, srv := newTestHandler(t, innerToken, preOwner)
	t.Cleanup(srv.Close)
	return srv, st
}
