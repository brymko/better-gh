package loginflow

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"better-gh/internal/policy"
)

// The owner console: after a GitHub sign-in proves the operator is the deployment owner, the
// /ui page becomes a small admin panel — list tokens, revoke, and create (form or pasted TOML
// spec). It is gated by a short-lived session cookie minted from an authenticated sign-in
// grant, so management actions need the same owner identity as the sign-in itself.

const (
	sessionCookie = "bgh_session"
	sessionTTL    = 30 * time.Minute
)

type session struct {
	login     string
	expiresAt time.Time
}

type sessionStore struct {
	mu     sync.Mutex
	byID   map[string]session
	ttl    time.Duration
	stopCh chan struct{}
}

func newSessionStore(ttl time.Duration) *sessionStore {
	s := &sessionStore{byID: make(map[string]session), ttl: ttl, stopCh: make(chan struct{})}
	go s.sweepLoop()
	return s
}

func (s *sessionStore) stop() { close(s.stopCh) }

func (s *sessionStore) create(login string) string {
	id := randHex(32)
	s.mu.Lock()
	s.byID[id] = session{login: login, expiresAt: time.Now().Add(s.ttl)}
	s.mu.Unlock()
	return id
}

func (s *sessionStore) lookup(id string) (string, bool) {
	if id == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.byID[id]
	if !ok || !sess.expiresAt.After(time.Now()) {
		return "", false
	}
	return sess.login, true
}

func (s *sessionStore) revoke(id string) {
	s.mu.Lock()
	delete(s.byID, id)
	s.mu.Unlock()
}

func (s *sessionStore) sweepLoop() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case now := <-t.C:
			s.mu.Lock()
			for id, sess := range s.byID {
				if !sess.expiresAt.After(now) {
					delete(s.byID, id)
				}
			}
			s.mu.Unlock()
		}
	}
}

// sessionLogin returns the owner login for a request's session cookie, or ("", false).
func (h *Handler) sessionLogin(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", false
	}
	return h.sessions.lookup(c.Value)
}

// apiSession upgrades an authenticated standalone sign-in grant into an owner session cookie,
// so the console's management endpoints can be used without re-running the sign-in each time.
func (h *Handler) apiSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GrantID string `json:"grant_id"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	var login, bsec string
	var ok bool
	h.grants.withGrant(byID(req.GrantID), func(g *grant) {
		if g.flow == "standalone" && (g.status == statusAuthenticated || g.status == statusApproved) {
			login, bsec, ok = g.login, g.browserSecret, true
		}
	})
	// Require the browser-binding cookie: only the browser that started the standalone sign-in may
	// upgrade it into an owner session, so a leaked grant_id cannot mint a session (audit F2). The
	// error is identical to the not-complete case to avoid an existence oracle on grant_id.
	if !ok || !grantCookieMatches(r, req.GrantID, bsec) {
		jsonResp(w, http.StatusForbidden, map[string]string{"error": "sign-in not complete"})
		return
	}
	id := h.sessions.create(login)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/ui", HttpOnly: true,
		Secure: h.cookieSecure(r), SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds()),
	})
	jsonResp(w, http.StatusOK, map[string]string{"login": login})
}

// cookieSecure marks the session cookie Secure when the deployment is reached over HTTPS
// (real serving, including behind a TLS-terminating front via external_url). Tests run over
// plain HTTP with no external_url, where Secure would stop the cookie being sent at all.
func (h *Handler) cookieSecure(r *http.Request) bool {
	return r.TLS != nil || strings.HasPrefix(h.ExternalURL, "https://")
}

// grantCookie binds an in-progress sign-in grant to the browser that started it (audit F2). Its
// value is "<grantID>.<browserSecret>"; setting it on the start/begin response and requiring it on
// apiSession/apiApprove means a leaked or guessed grant_id alone cannot mint a token or a session.
const grantCookie = "bgh_grant"

func (h *Handler) setGrantCookie(w http.ResponseWriter, r *http.Request, grantID, secret string) {
	http.SetCookie(w, &http.Cookie{
		Name: grantCookie, Value: grantID + "." + secret, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: h.cookieSecure(r), MaxAge: int(grantTTL.Seconds()),
	})
}

// grantCookieMatches reports whether r carries the browser-binding cookie for grantID with the
// matching secret (constant-time). A grant with no browserSecret never matches (fail closed).
func grantCookieMatches(r *http.Request, grantID, secret string) bool {
	if secret == "" {
		return false
	}
	c, err := r.Cookie(grantCookie)
	if err != nil {
		return false
	}
	want := grantID + "." + secret
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(want)) == 1
}

type repoOption struct {
	Name    string `json:"name"` // owner/repo
	Private bool   `json:"private"`
}

type accountResp struct {
	Login string       `json:"login"`
	Repos []repoOption `json:"repos"`
	Orgs  []string     `json:"orgs"`
}

// apiAccount returns the owner's own repos and orgs (fetched with the custodian token) so the
// console can prefill the repo/org pickers instead of making the operator type names.
func (h *Handler) apiAccount(w http.ResponseWriter, r *http.Request) {
	login, ok := h.sessionLogin(r)
	if !ok {
		jsonResp(w, http.StatusUnauthorized, map[string]string{"error": "sign in first"})
		return
	}
	repos := h.ownerRepos(r.Context())
	orgs := h.ownerOrgs(r.Context())
	// The owner's own login is a valid "org" target (it scopes their personal repos), so offer
	// it first in the org picker.
	orgs = append([]string{login}, orgs...)
	jsonResp(w, http.StatusOK, accountResp{Login: login, Repos: repos, Orgs: orgs})
}

// maxRepoPages caps the prefetch so a huge account can't make the console hang or balloon; the
// page notes when the list is truncated.
const maxRepoPages = 5

func (h *Handler) ownerRepos(ctx context.Context) []repoOption {
	tok := h.Owner.Token()
	out := []repoOption{}
	for page := 1; page <= maxRepoPages; page++ {
		body, err := h.githubGet(ctx, fmt.Sprintf(
			"/user/repos?per_page=100&page=%d&affiliation=owner,collaborator,organization_member&sort=pushed", page), tok)
		if err != nil {
			break
		}
		var repos []struct {
			FullName string `json:"full_name"`
			Private  bool   `json:"private"`
		}
		if json.Unmarshal(body, &repos) != nil {
			break
		}
		for _, rp := range repos {
			if rp.FullName != "" {
				out = append(out, repoOption{Name: rp.FullName, Private: rp.Private})
			}
		}
		if len(repos) < 100 {
			break
		}
	}
	return out
}

func (h *Handler) ownerOrgs(ctx context.Context) []string {
	body, err := h.githubGet(ctx, "/user/orgs?per_page=100", h.Owner.Token())
	if err != nil {
		return []string{}
	}
	var orgs []struct {
		Login string `json:"login"`
	}
	if json.Unmarshal(body, &orgs) != nil {
		return []string{}
	}
	out := []string{}
	for _, o := range orgs {
		if o.Login != "" {
			out = append(out, o.Login)
		}
	}
	return out
}

func (h *Handler) githubGet(ctx context.Context, path, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.APIBaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "bgh-proxy")
	resp, err := h.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github %s: %d", path, resp.StatusCode)
	}
	return body, nil
}

type tokenView struct {
	ID        string        `json:"id"`
	Name      string        `json:"name"`
	Policy    policy.Policy `json:"policy"`
	CreatedAt string        `json:"created_at"`
	LastUsed  string        `json:"last_used"`
	Revoked   bool          `json:"revoked"`
}

// apiListTokens returns every minted token (without secrets) for the console's manage view.
func (h *Handler) apiListTokens(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.sessionLogin(r); !ok {
		jsonResp(w, http.StatusUnauthorized, map[string]string{"error": "sign in first"})
		return
	}
	out := []tokenView{}
	for _, t := range h.Store.List() {
		lu := ""
		if !t.LastUsed.IsZero() {
			lu = t.LastUsed.UTC().Format(time.RFC3339)
		}
		out = append(out, tokenView{
			ID: t.ID, Name: t.Name, Policy: t.Policy,
			CreatedAt: t.CreatedAt.UTC().Format(time.RFC3339), LastUsed: lu, Revoked: t.Revoked,
		})
	}
	jsonResp(w, http.StatusOK, out)
}

// apiCreateToken mints a scoped token from either a structured policy (the builder) or a pasted
// TOML spec. A replace_id revokes that token after minting — the "edit = revoke + re-issue"
// path, so editing a token's permissions yields a fresh secret and kills the old one.
func (h *Handler) apiCreateToken(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.sessionLogin(r); !ok {
		jsonResp(w, http.StatusUnauthorized, map[string]string{"error": "sign in first"})
		return
	}
	var req struct {
		Name      string         `json:"name"`
		Policy    *policy.Policy `json:"policy"`
		SpecTOML  string         `json:"spec_toml"`
		ReplaceID string         `json:"replace_id"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	var pol policy.Policy
	switch {
	case strings.TrimSpace(req.SpecTOML) != "":
		p, err := policy.ParseTOML([]byte(req.SpecTOML))
		if err != nil {
			jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid TOML policy: " + err.Error()})
			return
		}
		pol = *p
	case req.Policy != nil:
		pol = *req.Policy
	default:
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "no policy provided"})
		return
	}
	ensureLoginUsable(&pol)
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "token-" + randHex(3)
	}
	tok, secret, err := h.Store.Create(name, pol)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "could not mint token"})
		return
	}
	if req.ReplaceID != "" {
		// edit = revoke + re-issue: the old token's secret must stop working now. Surface a
		// persist failure rather than swallow it (a silently-unrevoked old token would keep
		// authenticating, and resurrect on restart — audit F8).
		if _, err := h.Store.Revoke(req.ReplaceID); err != nil {
			jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "minted token but could not revoke the replaced one; revoke it manually"})
			return
		}
	}
	jsonResp(w, http.StatusOK, map[string]string{"id": tok.ID, "name": name, "secret": secret})
}

// apiParsePolicy parses a pasted TOML spec into a structured policy, so the console can switch
// from the TOML box back to the builder (and vice-versa) reusing the Go parser rather than a
// JS one. Returns 400 with the parse error on malformed TOML.
func (h *Handler) apiParsePolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.sessionLogin(r); !ok {
		jsonResp(w, http.StatusUnauthorized, map[string]string{"error": "sign in first"})
		return
	}
	var req struct {
		SpecTOML string `json:"spec_toml"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	p, err := policy.ParseTOML([]byte(req.SpecTOML))
	if err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	jsonResp(w, http.StatusOK, map[string]any{"policy": p})
}

// apiLogout ends the current owner session (and clears the cookie) — useful on a shared host.
func (h *Handler) apiLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		h.sessions.revoke(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/ui", MaxAge: -1,
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	jsonResp(w, http.StatusOK, map[string]string{"status": "signed out"})
}

// apiRevokeToken invalidates a token's secret immediately.
func (h *Handler) apiRevokeToken(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.sessionLogin(r); !ok {
		jsonResp(w, http.StatusUnauthorized, map[string]string{"error": "sign in first"})
		return
	}
	id := r.PathValue("id")
	ok, err := h.Store.Revoke(id)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "could not persist revocation"})
		return
	}
	if !ok {
		jsonResp(w, http.StatusNotFound, map[string]string{"error": "no such token"})
		return
	}
	jsonResp(w, http.StatusOK, map[string]string{"status": "revoked"})
}
