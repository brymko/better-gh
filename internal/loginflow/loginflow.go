package loginflow

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"better-gh/internal/oauth"
	"better-gh/internal/owner"
	"better-gh/internal/policy"
	"better-gh/internal/store"
)

const (
	githubBaseDefault = "https://github.com"
	apiBaseDefault    = "https://api.github.com"
	grantTTL          = 15 * time.Minute
	maxBody           = 1 << 20
)

//go:embed authorize.html
var authorizePage []byte

//go:embed ui.html
var uiPage []byte

// Handler implements the proxy's OAuth identity-provider endpoints under /login/*. It runs a
// GitHub device flow to authenticate the operator, applies it to the deployment owner store
// (the first sign-in claims the deployment and captures the GitHub token as the custodian;
// later sign-ins must be that same owner), then mints a scoped bgh_ token and returns it to gh.
type Handler struct {
	Store         *store.Store
	Owner         *owner.Store // TOFU owner; sign-in claims/refreshes the captured custodian token
	OAuthClientID string       // gh's public app id; no registration needed
	OAuthScopes   string       // scopes captured as the custodian (default "repo read:org gist workflow")
	GitHubBaseURL string       // device-flow base; default https://github.com (overridden in tests)
	APIBaseURL    string       // viewer{login} base; default https://api.github.com (overridden in tests)
	HTTPClient    *http.Client // used for the inner GitHub calls
	ExternalURL   string       // public base URL clients reach the proxy at, e.g. https://vps.tailnet.ts.net
	// Set when behind a TLS-terminating front (tailscale serve, Caddy): the device-flow
	// verification_uri the proxy hands gh must point at the public URL, not the backend the
	// front forwards to. Empty → derive from the request Host (correct for direct serving).

	mux      *http.ServeMux
	grants   *grantStore
	sessions *sessionStore // owner console sessions (minted after a verified sign-in)
}

func NewHandler(h *Handler) *Handler {
	if h.GitHubBaseURL == "" {
		h.GitHubBaseURL = githubBaseDefault
	}
	if h.APIBaseURL == "" {
		h.APIBaseURL = apiBaseDefault
	}
	if h.OAuthScopes == "" {
		// Captured as the custodian, so it must be broad enough to serve the proxy's traffic
		// — gh's own default scopes (the public app supports them via device flow).
		h.OAuthScopes = "repo read:org gist workflow"
	}
	if h.HTTPClient == nil {
		h.HTTPClient = http.DefaultClient
	}
	h.grants = newGrantStore(grantTTL)
	h.sessions = newSessionStore(sessionTTL)

	m := http.NewServeMux()
	m.HandleFunc("POST /login/device/code", h.deviceCode)
	m.HandleFunc("POST /login/oauth/access_token", h.accessToken)
	m.HandleFunc("GET /login/oauth/authorize", h.authorizePageWeb)
	m.HandleFunc("GET /login/device", h.authorizePageDevice)
	m.HandleFunc("POST /login/api/begin", h.apiBegin)
	m.HandleFunc("POST /login/api/poll", h.apiPoll)
	m.HandleFunc("POST /login/api/approve", h.apiApprove)
	// Owner console: sign in (start/poll), upgrade to a session, then manage tokens.
	m.HandleFunc("GET /ui", h.uiPageHandler)
	m.HandleFunc("POST /ui/api/start", h.apiStartStandalone)
	m.HandleFunc("POST /ui/api/poll", h.apiPoll)
	m.HandleFunc("POST /ui/api/session", h.apiSession)
	m.HandleFunc("GET /ui/api/account", h.apiAccount)
	m.HandleFunc("GET /ui/api/tokens", h.apiListTokens)
	m.HandleFunc("POST /ui/api/tokens", h.apiCreateToken)
	m.HandleFunc("DELETE /ui/api/tokens/{id}", h.apiRevokeToken)
	m.HandleFunc("POST /ui/api/policy/parse", h.apiParsePolicy)
	m.HandleFunc("POST /ui/api/logout", h.apiLogout)
	h.mux = m
	return h
}

func (h *Handler) Stop()                                            { h.grants.stop(); h.sessions.stop() }
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

// --- outer OAuth (gh <-> proxy) ---------------------------------------------------------

func (h *Handler) deviceCode(w http.ResponseWriter, r *http.Request) {
	g := &grant{flow: "device", userCode: randUserCode(), deviceCode: randHex(32), status: statusPending}
	h.grants.add(g)
	verURI := h.verificationBase(r) + "/login/device"
	jsonResp(w, http.StatusOK, map[string]any{
		"device_code":               g.deviceCode,
		"user_code":                 g.userCode,
		"verification_uri":          verURI,
		"verification_uri_complete": verURI + "?user_code=" + g.userCode,
		"expires_in":                int(grantTTL.Seconds()),
		"interval":                  5,
	})
}

// accessToken is what gh polls (device) or exchanges (web). It returns the minted bgh_ token
// once the grant is approved, or an OAuth device-flow status otherwise (HTTP 200 + {error}).
func (h *Handler) accessToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	deviceCode := r.PostForm.Get("device_code")
	code := r.PostForm.Get("code")

	var match func(*grant) bool
	switch {
	case deviceCode != "":
		match = byDeviceCode(deviceCode)
	case code != "":
		match = byAuthCode(code)
	default:
		jsonResp(w, http.StatusOK, map[string]string{"error": "invalid_request"})
		return
	}

	var secret, errCode, grantID string
	found := h.grants.withGrant(match, func(g *grant) {
		switch g.status {
		case statusApproved:
			secret, grantID = g.secret, g.id
		case statusDenied:
			errCode = "access_denied"
		default:
			errCode = "authorization_pending"
		}
	})
	if !found {
		// unknown/expired code: device flow reads this as the code having expired.
		jsonResp(w, http.StatusOK, map[string]string{"error": "expired_token"})
		return
	}
	if errCode != "" {
		jsonResp(w, http.StatusOK, map[string]string{"error": errCode})
		return
	}
	h.grants.remove(grantID) // one-time issuance: a replayed exchange can't re-fetch the secret
	jsonResp(w, http.StatusOK, map[string]string{
		"access_token": secret,
		"token_type":   "bearer",
		"scope":        "repo,read:org,gist",
	})
}

// verificationBase is the public base URL the device-flow verification_uri is built from:
// the configured ExternalURL when set (required behind a TLS-terminating front), otherwise
// derived from the request — correct when the proxy is served directly.
func (h *Handler) verificationBase(r *http.Request) string {
	if h.ExternalURL != "" {
		return strings.TrimRight(h.ExternalURL, "/")
	}
	return "https://" + r.Host
}

func (h *Handler) authorizePageDevice(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(authorizePage)
}

func (h *Handler) uiPageHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(uiPage)
}

// apiStartStandalone backs the web "create a token" page: it creates a standalone grant (not
// tied to a gh OAuth flow) and starts the GitHub device flow to sign the operator in. The
// minted secret is returned to the browser by apiApprove rather than handed to gh.
func (h *Handler) apiStartStandalone(w http.ResponseWriter, r *http.Request) {
	g := &grant{flow: "standalone", status: statusPending, started: true}
	h.grants.add(g)
	userCode, verification, err := h.runGitHubAuth(g.id)
	if err != nil {
		h.grants.remove(g.id)
		jsonResp(w, http.StatusBadGateway, map[string]string{"error": "could not start GitHub login: " + err.Error()})
		return
	}
	jsonResp(w, http.StatusOK, map[string]any{
		"grant_id":            g.id,
		"github_user_code":    userCode,
		"github_verification": verification,
	})
}

// runGitHubAuth starts GitHub's device flow for a grant and returns the user code + verification
// URI to show the operator. The flow itself runs in a background goroutine that REUSES
// oauth.DeviceFlow (the same poll loop gh uses, including its interval/slow_down backoff); once
// GitHub authorizes, it applies the sign-in to the owner store (first sign-in claims the
// deployment, captures the token as custodian; later sign-ins must be that same owner) and
// settles the grant's status. The page never drives GitHub's cadence — it just polls our status.
func (h *Handler) runGitHubAuth(grantID string) (userCode, verification string, err error) {
	type codeInfo struct{ code, url string }
	codeCh := make(chan codeInfo, 1)
	errCh := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), grantTTL)

	go func() {
		defer cancel()
		token, ferr := oauth.DeviceFlow(ctx, oauth.Config{
			ClientID: h.OAuthClientID, Scopes: h.OAuthScopes,
			BaseURL: h.GitHubBaseURL, Client: h.HTTPClient, Out: io.Discard,
			OnCode: func(code, url string) { codeCh <- codeInfo{code, url} },
		})
		if ferr != nil {
			select { // surfaced to the caller only if it happened before we got a code
			case errCh <- ferr:
			default:
			}
			h.denyGrant(grantID, "GitHub authorization failed: "+ferr.Error())
			return
		}
		who, rerr := h.resolveLogin(ctx, token)
		if rerr != nil {
			h.denyGrant(grantID, "could not read your GitHub identity")
			slog.Info("loginflow: could not read GitHub identity", "grant", grantID, "err", rerr)
			return
		}
		if _, ok, serr := h.Owner.SignIn(who, token); serr != nil {
			h.denyGrant(grantID, "could not record the sign-in")
			slog.Info("loginflow: could not record sign-in", "grant", grantID, "err", serr)
			return
		} else if !ok {
			h.denyGrant(grantID, fmt.Sprintf("%q is not the owner of this deployment", who))
			return
		}
		h.grants.withGrant(byID(grantID), func(g *grant) {
			if g.status == statusPending {
				g.status, g.login = statusAuthenticated, who
			}
		})
	}()

	select {
	case ci := <-codeCh:
		return ci.code, ci.url, nil
	case e := <-errCh:
		return "", "", e
	case <-time.After(20 * time.Second):
		return "", "", fmt.Errorf("timed out starting GitHub device flow")
	}
}

// denyGrant settles a still-pending grant as denied with a reason for the page to display.
func (h *Handler) denyGrant(grantID, reason string) {
	h.grants.withGrant(byID(grantID), func(g *grant) {
		if g.status == statusPending {
			g.status, g.denyReason = statusDenied, reason
		}
	})
}

// authorizePageWeb handles gh's browser (web) flow: record the grant keyed by gh's state +
// callback, then serve the same authorize page (it reads state from the URL).
func (h *Handler) authorizePageWeb(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	redirectURI := q.Get("redirect_uri")
	if state == "" || redirectURI == "" {
		http.Error(w, "missing state or redirect_uri", http.StatusBadRequest)
		return
	}
	g := &grant{flow: "web", state: state, redirectURI: redirectURI, userCode: randUserCode(), status: statusPending}
	h.grants.add(g)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(authorizePage)
}

// --- authorize page AJAX -----------------------------------------------------------------

type beginReq struct {
	UserCode string `json:"user_code"`
	State    string `json:"state"`
}

// apiBegin looks up the grant the operator is authorizing and starts the inner GitHub device
// flow, returning the GitHub code/URL for the page to display.
func (h *Handler) apiBegin(w http.ResponseWriter, r *http.Request) {
	var req beginReq
	if !readJSON(w, r, &req) {
		return
	}
	match := byUserCode(strings.ToUpper(strings.TrimSpace(req.UserCode)))
	if req.State != "" {
		match = byState(req.State)
	}

	var id, userCode string
	var alreadyStarted bool
	found := h.grants.withGrant(match, func(g *grant) {
		id, userCode, alreadyStarted = g.id, g.userCode, g.started
		if !g.started {
			g.started = true // claim the start under the lock so concurrent begins don't double-launch
		}
	})
	if !found {
		jsonResp(w, http.StatusNotFound, map[string]string{"error": "unknown or expired code"})
		return
	}
	if alreadyStarted {
		// idempotent on page reload: we can't recover GitHub's user_code, so tell the page it's
		// already in progress and to keep polling.
		jsonResp(w, http.StatusOK, map[string]any{"grant_id": id, "user_code": userCode, "in_progress": true})
		return
	}

	ghUserCode, ghVerification, err := h.runGitHubAuth(id)
	if err != nil {
		h.grants.withGrant(byID(id), func(g *grant) { g.started = false }) // allow a retry
		jsonResp(w, http.StatusBadGateway, map[string]string{"error": "could not start GitHub login: " + err.Error()})
		return
	}
	jsonResp(w, http.StatusOK, map[string]any{
		"grant_id":            id,
		"user_code":           userCode,
		"github_user_code":    ghUserCode,
		"github_verification": ghVerification,
	})
}

// apiPoll reports the current status of a sign-in grant. The GitHub device flow runs in the
// background (see runGitHubAuth) — this endpoint never talks to GitHub; the page just polls
// here until the grant settles to authenticated or denied.
func (h *Handler) apiPoll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		GrantID string `json:"grant_id"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	var login, denyReason string
	var st grantStatus
	found := h.grants.withGrant(byID(req.GrantID), func(g *grant) {
		st, login, denyReason = g.status, g.login, g.denyReason
	})
	if !found {
		jsonResp(w, http.StatusNotFound, map[string]string{"status": "expired"})
		return
	}
	switch st {
	case statusAuthenticated, statusApproved:
		jsonResp(w, http.StatusOK, map[string]string{"status": "authenticated", "login": login})
	case statusDenied:
		if denyReason == "" {
			denyReason = "GitHub login is not the owner of this deployment"
		}
		jsonResp(w, http.StatusOK, map[string]string{"status": "denied", "error": denyReason})
	default:
		jsonResp(w, http.StatusOK, map[string]string{"status": "pending"})
	}
}

type approveReq struct {
	GrantID string        `json:"grant_id"`
	Name    string        `json:"name"`
	Policy  policy.Policy `json:"policy"`
}

// apiApprove mints the scoped proxy token for an authenticated grant and records the secret
// (device) or an auth code + redirect (web) for gh to collect.
func (h *Handler) apiApprove(w http.ResponseWriter, r *http.Request) {
	var req approveReq
	if !readJSON(w, r, &req) {
		return
	}
	// Reserve the grant for minting (only from the authenticated state) so a double-submit
	// can't mint twice.
	var ok bool
	var login, flow, redirectURI, state string
	h.grants.withGrant(byID(req.GrantID), func(g *grant) {
		if g.status == statusAuthenticated {
			g.status = statusApproved // provisional; secret filled in below
			ok, login, flow, redirectURI, state = true, g.login, g.flow, g.redirectURI, g.state
		}
	})
	if !ok {
		jsonResp(w, http.StatusConflict, map[string]string{"error": "grant is not authenticated (authorize with GitHub first)"})
		return
	}

	pol := req.Policy
	ensureLoginUsable(&pol)
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "ghlogin-" + login
	}
	_, secret, err := h.Store.Create(name, pol)
	if err != nil {
		h.grants.withGrant(byID(req.GrantID), func(g *grant) { g.status = statusAuthenticated }) // revert
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "could not mint token"})
		return
	}

	var authCode string
	if flow == "web" {
		authCode = randHex(32)
	}
	h.grants.withGrant(byID(req.GrantID), func(g *grant) {
		g.secret, g.authCode = secret, authCode
	})

	if flow == "web" {
		sep := "?"
		if strings.Contains(redirectURI, "?") {
			sep = "&"
		}
		jsonResp(w, http.StatusOK, map[string]string{
			"status":   "approved",
			"redirect": redirectURI + sep + "code=" + authCode + "&state=" + state,
		})
		return
	}
	jsonResp(w, http.StatusOK, map[string]string{"status": "approved"})
}

// --- identity --------------------------------------------------------------------------

// resolveLogin returns viewer{login} for a token via GitHub's GraphQL API.
func (h *Handler) resolveLogin(ctx context.Context, token string) (string, error) {
	body, _ := json.Marshal(map[string]string{"query": "{viewer{login}}"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.APIBaseURL+"/graphql", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "bgh-proxy")
	resp, err := h.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return "", err
	}
	var parsed struct {
		Data struct {
			Viewer struct {
				Login string `json:"login"`
			} `json:"viewer"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", err
	}
	return parsed.Data.Viewer.Login, nil
}

// ensureLoginUsable guarantees the minted token can complete gh's post-login checks: gh runs
// {viewer{login}} (unscoped "user") right after login, and the GHE handshake reads "meta". A
// token denied those can never finish `gh auth login`, so we raise them to at least read.
func ensureLoginUsable(p *policy.Policy) {
	if p.Defaults.Unscoped == nil {
		p.Defaults.Unscoped = map[string]policy.Access{}
	}
	for _, cat := range []string{"user", "meta"} {
		if p.Defaults.Unscoped[cat] < policy.AccessRead {
			p.Defaults.Unscoped[cat] = policy.AccessRead
		}
	}
}

// --- helpers ---------------------------------------------------------------------------

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, maxBody)).Decode(v); err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return false
	}
	return true
}

func jsonResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
