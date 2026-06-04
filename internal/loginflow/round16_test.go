package loginflow

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Round-16 (test-gap): the owner console's CSRF defense is the cookie attributes alone (there is no
// CSRF token / Origin check), so SameSite=Strict + HttpOnly on the grant cookie (gates token minting
// via apiApprove/apiSession) and the session cookie (gates /ui/api/tokens) MUST be asserted — a
// refactor that weakened them to Lax/None would silently make the console CSRF-mintable.
func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestGrantCookieIsStrictHttpOnlySecure(t *testing.T) {
	h := &Handler{ExternalURL: "https://proxy.example"}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ui/api/start", nil)
	req.TLS = &tls.ConnectionState{}
	h.setGrantCookie(rec, req, "gid", "bsecret")

	c := findCookie(rec.Result().Cookies(), grantCookie)
	if c == nil {
		t.Fatal("grant cookie not set")
	}
	if !c.HttpOnly {
		t.Error("grant cookie must be HttpOnly")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("grant cookie must be SameSite=Strict, got %v", c.SameSite)
	}
	if !c.Secure {
		t.Error("grant cookie must be Secure over TLS")
	}
}

func TestSessionCookieIsStrictHttpOnly(t *testing.T) {
	h := NewHandler(&Handler{ExternalURL: "https://proxy.example"})
	// Pre-seed an authenticated standalone grant bound to this browser.
	g := &grant{flow: "standalone", status: statusAuthenticated, login: "owner-login", browserSecret: "bsecret"}
	if !h.grants.add(g) {
		t.Fatal("could not add grant")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/ui/api/session", strings.NewReader(`{"grant_id":"`+g.id+`"}`))
	req.TLS = &tls.ConnectionState{}
	req.AddCookie(&http.Cookie{Name: grantCookie, Value: g.id + "." + g.browserSecret})
	h.apiSession(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("apiSession should succeed for a bound authenticated grant, got %d: %s", rec.Code, rec.Body.String())
	}
	c := findCookie(rec.Result().Cookies(), sessionCookie)
	if c == nil {
		t.Fatal("session cookie not set")
	}
	if !c.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Errorf("session cookie must be SameSite=Strict (the /ui CSRF defense), got %v", c.SameSite)
	}
	if !c.Secure {
		t.Error("session cookie must be Secure over TLS")
	}
}
