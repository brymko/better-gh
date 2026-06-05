package loginflow

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Round-20: resolveLogin is the deployment-ownership boundary, so it must HARD-error on a non-200, a
// GraphQL errors array, or an empty login — never silently return an empty identity downstream code
// must remember to reject.
func TestR20_ResolveLoginRejectsErrorResponses(t *testing.T) {
	bad := []struct {
		name   string
		status int
		body   string
	}{
		{"non-200", http.StatusUnauthorized, `{"message":"Bad credentials"}`},
		{"graphql-errors", http.StatusOK, `{"errors":[{"message":"Bad credentials"}]}`},
		{"empty-login", http.StatusOK, `{"data":{"viewer":{"login":""}}}`},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(c.status)
				io.WriteString(w, c.body)
			}))
			defer srv.Close()
			h := &Handler{APIBaseURL: srv.URL, HTTPClient: srv.Client()}
			if login, err := h.resolveLogin(context.Background(), "tok"); err == nil {
				t.Fatalf("resolveLogin(%s) must error, got login=%q", c.name, login)
			}
		})
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"data":{"viewer":{"login":"octocat"}}}`)
	}))
	defer srv.Close()
	h := &Handler{APIBaseURL: srv.URL, HTTPClient: srv.Client()}
	login, err := h.resolveLogin(context.Background(), "tok")
	if err != nil || login != "octocat" {
		t.Fatalf("resolveLogin happy path: login=%q err=%v", login, err)
	}
}

// Round-20: the grant consume must hand a minted secret out exactly once — a second exchange of the
// same device_code (after the first consumed the grant) sees it gone (expired_token).
func TestR20_GrantConsumeOneTime(t *testing.T) {
	gs := newGrantStore(grantTTL)
	defer gs.stop()
	g := &grant{flow: "device", deviceCode: "dc123", status: statusApproved, secret: "bgh_minted"}
	if !gs.add(g) {
		t.Fatal("add grant")
	}

	read := func() (secret string, found bool) {
		found = gs.consume(byDeviceCode("dc123"), func(g *grant) bool {
			if g.status == statusApproved && g.secret != "" {
				secret = g.secret
				return true
			}
			return false
		})
		return
	}
	if s, ok := read(); !ok || s != "bgh_minted" {
		t.Fatalf("first consume: secret=%q found=%v", s, ok)
	}
	if _, ok := read(); ok {
		t.Fatal("second consume of a one-time grant must not find it (already consumed)")
	}
}
