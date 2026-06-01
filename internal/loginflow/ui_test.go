package loginflow

import (
	"net/http"
	"strings"
	"testing"
)

// The web "create a token" page: GET /ui serves it; the standalone flow starts a GitHub
// sign-in, the owner gate applies, and approval returns the minted secret to the browser.
func TestStandaloneCreateToken(t *testing.T) {
	srv, st := newServerOnly(t, "tok-alice", "") // unclaimed → first sign-in claims alice

	// The page is served.
	resp, err := http.Get(srv.URL + "/ui")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /ui status %d", resp.StatusCode)
	}

	// Start a standalone sign-in (no gh involved).
	_, s := post(t, srv, "/ui/api/start", map[string]string{})
	grantID, _ := s["grant_id"].(string)
	if grantID == "" || s["github_user_code"] == nil {
		t.Fatalf("start missing grant_id/github_user_code: %v", s)
	}

	// Poll → GitHub returns tok-alice; first sign-in claims the deployment → authenticated.
	_, p := post(t, srv, "/ui/api/poll", map[string]string{"grant_id": grantID})
	if p["status"] != "authenticated" || p["login"] != "alice" {
		t.Fatalf("expected authenticated as alice, got %v", p)
	}

	// Approve with a policy → the secret is returned to the browser (not handed to gh).
	pol := map[string]any{"defaults": map[string]any{"mode": "deny"}, "repo": []map[string]string{{"name": "alice/app", "access": "read"}}}
	_, ap := post(t, srv, "/ui/api/approve", map[string]any{"grant_id": grantID, "name": "web-token", "policy": pol})
	secret, _ := ap["secret"].(string)
	if secret == "" {
		t.Fatalf("approve did not return a secret: %v", ap)
	}
	tok := st.Lookup(secret)
	if tok == nil || tok.Name != "web-token" {
		t.Fatalf("minted secret does not resolve to the named token: %+v", tok)
	}
	if len(tok.Policy.Repo) != 1 || !strings.EqualFold(tok.Policy.Repo[0].Name, "alice/app") {
		t.Fatalf("policy not applied: %+v", tok.Policy)
	}
}

// A non-owner cannot create a token via the web page either.
func TestStandaloneNonOwnerDenied(t *testing.T) {
	srv, st := newServerOnly(t, "tok-bob", "alice") // deployment pre-claimed by alice

	_, s := post(t, srv, "/ui/api/start", map[string]string{})
	grantID := s["grant_id"].(string)
	_, p := post(t, srv, "/ui/api/poll", map[string]string{"grant_id": grantID})
	if p["status"] != "denied" {
		t.Fatalf("non-owner must be denied, got %v", p)
	}
	code, _ := post(t, srv, "/ui/api/approve", map[string]any{"grant_id": grantID, "policy": map[string]any{}})
	if code != http.StatusConflict {
		t.Fatalf("approve on denied grant should be 409, got %d", code)
	}
	if len(st.List()) != 0 {
		t.Fatalf("a token was minted for a non-owner: %d", len(st.List()))
	}
}
